"""
schema.py — Policy Engine 的「輸出契約」(Structured Output Schema)

這個檔案定義了:LLM 審查完一次 tool call 之後，必須吐回來的 JSON 長什麼樣子。

為什麼要先寫這個？
  因為整個系統的可靠性都建立在「LLM 的輸出可以被程式確定性地解析」之上。
  如果 LLM 今天回 "block"、明天回 "I think you should block this..."，
  後面的評估程式(算 F1、FPR)就完全沒辦法自動跑。
  所以我們用 Pydantic 把輸出「鎖死」成固定格式，不符合就報錯、重試。

對應你個人報告第五章的七欄位設計。
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────
# 1. 用 Enum 把「合法值」鎖死
#    Enum = 列舉，意思是「這個欄位只能是這幾個值之一，其他都不准」。
#    繼承 str 是 Pydantic v2 的常見技巧：這樣序列化成 JSON 時會直接變成
#    字串 "allow"，而不是奇怪的 Decision.ALLOW 物件。
# ──────────────────────────────────────────────────────────────

class Decision(str, Enum):
    """最終裁決：放行 / 需二次確認 / 封鎖。

    三值設計（而非單純 allow/block 二元）是你報告裡的關鍵設計：
    require_confirmation 提供中間緩衝，預期可降低 False Positive Rate。
    """
    ALLOW = "allow"
    REQUIRE_CONFIRMATION = "require_confirmation"
    BLOCK = "block"


class RiskLevel(str, Enum):
    """風險等級。與 decision 分開記錄，是為了能標記
    「允許但風險偏高」的情況，供後續稽核(audit)追蹤。"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    """偵測到的攻擊類型。

    【已對齊後端 API】後端按「攻擊效果」分類(而非攻擊手法)，
    本模組改採同一套值，以便 POST /tool/call 直接串接。
      - none               : 良性請求(後端用字串 "none" 而非 null)
      - prompt_injection   : 指令注入(含直接惡意指令、間接注入、身份偽裝
                             等「以注入手段操控 agent」的攻擊)
      - data_exfiltration  : 資料外洩(把敏感資料送往外部)
      - destructive_action : 破壞性操作(刪除/覆寫等不可逆動作)
    """
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    DESTRUCTIVE_ACTION = "destructive_action"


class PolicyViolation(str, Enum):
    """違反了哪一條政策。可被查詢(queryable)的分類，
    支援之後的 audit log 分析。良性請求時為 None。"""
    DATA_EXFILTRATION = "data_exfiltration"      # 資料外洩
    UNAUTHORIZED_DELETE = "unauthorized_delete"  # 未授權刪除
    IDENTITY_SPOOFING = "identity_spoofing"      # 身份偽裝
    PROMPT_INJECTION = "prompt_injection"        # 指令注入（對齊 AttackType）


# ──────────────────────────────────────────────────────────────
# 2. 主 Schema：把上面的欄位組成一張「裁決表單」
#    BaseModel 是 Pydantic 的核心。繼承它之後，這個類別就會自動
#    幫你做型別驗證、JSON 轉換、錯誤回報。
# ──────────────────────────────────────────────────────────────

class PolicyDecision(BaseModel):
    """Policy Engine 對單一 tool call 的完整裁決結果。

    這就是我們要求 LLM「填好並交回來」的那張表單。
    """

    decision: Decision = Field(
        ...,  # "..." 代表這個欄位「必填」，沒有預設值
        description="最終裁決：allow / require_confirmation / block",
    )

    risk_level: RiskLevel = Field(
        ...,
        description="風險等級：low / medium / high / critical",
    )

    attack_type: AttackType = Field(
        default=AttackType.NONE,  # 對齊後端:良性請求用 "none" 而非 null
        description='偵測到的攻擊類型；良性請求為 "none"',
    )

    intent_match: bool = Field(
        ...,
        description="tool call 是否符合使用者原始意圖(可程式化的一致性指標)",
    )

    evidence: str = Field(
        ...,
        max_length=500,  # 刻意限制長度：要「簡短理由」而非完整 CoT
        description=(
            "簡短的判斷依據。刻意不要求完整 chain-of-thought，"
            "以降低攻擊者反推 policy engine 邏輯的風險。"
        ),
    )

    rationale: Optional[str] = Field(
        default=None,
        description="裁決原因的完整說明，對應後端 API rationale 欄位。選填：MockLLM 階段可為 None，真實 LLM 階段建議必填。",
    )

    recommended_action: str = Field(
        ...,
        description="具體的緩解建議，供 human-in-the-loop 確認流程使用",
    )

    policy_violation: Optional[PolicyViolation] = Field(
        default=None,
        description="違反的政策分類；良性請求為 null",
    )

    # model_config 是 Pydantic v2 設定行為的地方。
    # extra="forbid" 表示：如果 LLM 多吐了我們沒定義的欄位，直接報錯。
    # 這對資安系統很重要 —— 我們不希望「悄悄多出來的欄位」被忽略。
    model_config = {
        "extra": "forbid",
    }


# ──────────────────────────────────────────────────────────────
# 3. 一個小工具：把 LLM 回傳的原始字串安全地轉成 PolicyDecision
#    LLM 有時會在 JSON 前後多包一層 ```json ... ``` 的 Markdown 圍欄，
#    這個函式先把圍欄清掉再解析。
# ──────────────────────────────────────────────────────────────

def parse_llm_output(raw: str) -> PolicyDecision:
    """把 LLM 回傳的原始文字解析成 PolicyDecision。

    若格式不合法，Pydantic 會丟出 ValidationError —
    這正是我們要的：壞掉就明確報錯，好讓上層去重試。
    """
    text = raw.strip()

    # 清掉可能的 Markdown code fence: ```json ... ```
    if text.startswith("```"):
        # 去掉第一行(```json 或 ```)和最後的 ```
        lines = text.splitlines()
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # model_validate_json 會同時做「JSON 解析 + 型別驗證」
    return PolicyDecision.model_validate_json(text)