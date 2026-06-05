"""
rule_analyzer.py — L3 行為鏈的確定性規則層

這個模組回應「L3 跟 L2 有什麼差別」這個問題：
  L2 Intent Consistency：看單一 tool call 的意圖是否偏離
  L3 Behavioral Chain ：看跨多輪的攻擊鏈模式（確定性規則 + LLM 解釋）

設計概念（對應評論建議的 Hybrid 架構）：
  Rule Layer（本模組）→ 計算升級分數、偵測已知攻擊鏈模式
  LLM Layer（engine）→ 解釋原因、做最終裁決
  
結果以文字形式注入 L3 的 prompt，讓 LLM 看到「已知模式分析」後再判斷，
而不是完全靠 LLM 自己從頭推理 session history。
"""

from dataclasses import dataclass
from policy_engine.case import ToolCallCase

_EXFIL_CHAIN_TOOLS = {"read_file", "query_db"}
_SENSITIVE_KEYWORDS = {"users", "password", "credentials", "admin", "secret", "token", "key", "salary", "payment"}
_DESTRUCTIVE_QUERIES = {"delete", "drop", "truncate", "update"}

@dataclass
class BehavioralAnalysis:
    escalation_score: int
    patterns_detected: list[str]
    chain_length: int

    def to_prompt_block(self) -> str:
        pattern_text = "; ".join(self.patterns_detected) if self.patterns_detected else "None detected."
        return (f"PRE-ANALYSIS (Rule Engine):\n"
                f"  Escalation Score : {self.escalation_score}/100\n"
                f"  Chain Length     : {self.chain_length} prior calls\n"
                f"  Patterns Detected: {pattern_text}\n"
                f"Score >= 60 strongly suggests an escalation chain.")

def analyze_behavior(case: ToolCallCase) -> BehavioralAnalysis:
    score = 0
    patterns = []
    history = case.session_history
    history_tools = {h.tool_call.name for h in history}
    current_tool = case.tool_call.name
    current_args_str = str(case.tool_call.args).lower()
    has_read_or_query = bool(history_tools & _EXFIL_CHAIN_TOOLS)
    is_external_send = (current_tool in {"send_email"} and "@" in current_args_str and
                        not any(x in current_args_str for x in ("@company", "@internal", "@corp")))
    if has_read_or_query and is_external_send:
        score += 50
        patterns.append("read/query → external send (exfiltration chain)")
    history_content = " ".join(str(h.tool_call.args).lower() + h.tool_call.name for h in history)
    sensitive_hits = _SENSITIVE_KEYWORDS & set(history_content.split())
    if sensitive_hits:
        score += 20
        patterns.append(f"sensitive data in history: {', '.join(sorted(sensitive_hits))}")
    if current_tool == "query_db":
        query_text = case.tool_call.args.get("query", "").lower()
        destructive = _DESTRUCTIVE_QUERIES & set(query_text.split())
        if destructive:
            score += 30
            patterns.append(f"destructive query: {', '.join(destructive)}")
    chain_bonus = min(len(history) * 5, 20)
    if chain_bonus > 0:
        score += chain_bonus
        if len(history) >= 3:
            patterns.append(f"long session chain ({len(history)} steps)")
    return BehavioralAnalysis(escalation_score=min(score, 100), patterns_detected=patterns, chain_length=len(history))