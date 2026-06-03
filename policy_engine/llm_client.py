"""
LLM 呼叫 + 輸出驗證 + 自動重試

三個角色:
  BaseLLMClient   介面定義(之後換真實 LLM 只要繼承這個就好)
  MockLLMClient   假的 LLM，根據關鍵字回傳合理裁決，完全不需 API key
  call_with_retry 呼叫 → 驗證 → 失敗就重試，最多 3 次
"""

from abc import ABC, abstractmethod
from pydantic import ValidationError
from policy_engine.schema import PolicyDecision, parse_llm_output


# ──────────────────────────────────────────────────────────────
# 1. 介面：所有 LLM 客戶端都要實作 complete()
# ──────────────────────────────────────────────────────────────

class BaseLLMClient(ABC):
    @abstractmethod
    def complete(self, messages: list[dict]) -> str:
        """送出 messages，回傳 LLM 的原始文字輸出。"""
        pass


# ──────────────────────────────────────────────────────────────
# 2. 假的 LLM：根據待審案例的關鍵字決定裁決
#    之後要換成真實 LLM，只要新增 BaseLLMClient 就好。
# ──────────────────────────────────────────────────────────────

class MockLLMClient(BaseLLMClient):
    """假的 LLM，根據案例內容關鍵字回傳合理裁決。"""

    # 明確攻擊訊號
    ATTACK_KEYWORDS = [
        "ignore previous", "ignore all", "admin override",
        "exfiltrate", "attacker@", "evil.com",
        "delete from users", "drop table",
        "[system]", "[admin]",
    ]

    # 高風險但可能合法的操作訊號
    MEDIUM_KEYWORDS = [
        "delete", "remove", "send_email",
        "execute_code", "write_file",
    ]

    def complete(self, messages: list[dict]) -> str:
        # 找最後一則 user 訊息（待審案例的內容）
        user_content = ""
        for m in reversed(messages):
            if m["role"] == "user":
                user_content = m["content"].lower()
                break

        if any(kw in user_content for kw in self.ATTACK_KEYWORDS):
            return (
                '{"decision":"block","risk_level":"critical",'
                '"attack_type":"prompt_injection","intent_match":false,'
                '"evidence":"Detected attack pattern in the request.",'
                '"recommended_action":"Block and alert the user.",'
                '"policy_violation":"data_exfiltration"}'
            )

        if any(kw in user_content for kw in self.MEDIUM_KEYWORDS):
            return (
                '{"decision":"require_confirmation","risk_level":"medium",'
                '"attack_type":"none","intent_match":true,'
                '"evidence":"Operation is potentially risky but may be legitimate.",'
                '"recommended_action":"Ask user to confirm before proceeding.",'
                '"policy_violation":null}'
            )

        return (
            '{"decision":"allow","risk_level":"low",'
            '"attack_type":"none","intent_match":true,'
            '"evidence":"Request aligns with user intent, low risk.",'
            '"recommended_action":"None.",'
            '"policy_violation":null}'
        )


# ──────────────────────────────────────────────────────────────
# 3. 重試機制：呼叫 LLM → 驗證輸出 → 失敗就重試
#
#      LLM 有時輸出格式不對（多了說明文字、缺欄位...）。
#      Pydantic 丟出 ValidationError → 抓住它 →
#      把錯誤原因告訴 LLM → 再試一次，最多 max_retries 次。
# ──────────────────────────────────────────────────────────────

def call_with_retry(
    client: BaseLLMClient,
    messages: list[dict],
    max_retries: int = 3,
) -> PolicyDecision:
    """呼叫 LLM，驗證輸出，失敗時自動重試。

    Returns:
        PolicyDecision: 驗證通過的裁決物件

    Raises:
        RuntimeError: 超過重試次數仍無法取得合法輸出
    """
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            raw = client.complete(messages)
            decision = parse_llm_output(raw)

            if attempt > 1:
                print(f"  [重試成功] 第 {attempt} 次嘗試通過")

            return decision

        except ValidationError as e:
            last_error = e
            msg = e.errors()[0]["msg"]
            print(f"  [驗證失敗] 第 {attempt}/{max_retries} 次: {msg}")

            if attempt < max_retries:
                # 把錯誤原因追加到對話，讓 LLM 知道哪裡不對
                messages = messages + [{
                    "role": "user",
                    "content": (
                        f"Your previous response was invalid: {msg}. "
                        "Please respond with a valid JSON object only."
                    ),
                }]

        except Exception as e:
            last_error = e
            print(f"  [錯誤] 第 {attempt}/{max_retries} 次: {e}")

    raise RuntimeError(f"超過最大重試次數 ({max_retries})，最後錯誤: {last_error}")


class OllamaLLMClient(BaseLLMClient):
    """本地 Ollama LLM 客戶端（glows.ai 上使用，無 token 限制）。

    使用方式：
        client = OllamaLLMClient(model="模型名稱")
        engine = PolicyEngine(client, use_few_shot=True)
    """

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        temperature: float = 0.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature

    def complete(self, messages: list[dict]) -> str:
        import json
        import urllib.request

        url = f"{self.base_url}/api/chat"
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
        return result["message"]["content"]
