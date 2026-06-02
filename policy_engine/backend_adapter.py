"""
本模組格式 <-> 後端 API 格式
對齊依據:API_介接說明文件.pdf 第 3 章。
"""

import json

from policy_engine.case import ToolCallCase
from policy_engine.schema import PolicyDecision


# 後端 query_db 用 "query" 這個 key;本模組範例裡常用 "sql"。
# 這個函式把工具參數正規化成後端要的樣子。
def _normalize_params(tool_name: str, args: dict) -> dict:
    args = dict(args)  # 複製，不動到原物件
    if tool_name == "query_db":
        # 後端要 {"query": ..., "database": ...}
        if "sql" in args and "query" not in args:
            args["query"] = args.pop("sql")
        args.setdefault("database", "users")  # 文件範例的預設
    return args


def to_tool_call_request(
    case: ToolCallCase,
    session_id: str,
) -> dict:
    """把一個待審案例，轉成後端 POST /tool/call 的 request body。

    注意:後端會自己跑它的 Layer-1 Input Scan 並回傳裁決。
          我們送的是「要執行的 tool call + 使用者原始輸入」。
    """
    return {
        "session_id": session_id,
        "tool_name": case.tool_call.name,
        "parameters": _normalize_params(case.tool_call.name, case.tool_call.args),
        "user_prompt": case.user_message,
        "agent_context": case.external_content,  # 外部內容當作 agent context
    }


def decision_to_backend_fields(decision: PolicyDecision) -> dict:
    """把 PolicyDecision 翻成後端欄位命名。

    對應後端 /tool/call 的 Response 欄位:
      - 後端有 rationale(裁決原因) + evidence;本模組只有 evidence
        → 用 evidence 同時填 rationale
      - policy_violation 後端為自由字串;本模組是 enum，輸出其 value。
    """
    return {
        "decision": decision.decision.value,
        "risk_level": decision.risk_level.value,
        "attack_type": decision.attack_type.value,   # 已對齊後端值
        "intent_match": decision.intent_match,
        "evidence": decision.evidence,
        "rationale": decision.evidence,              # 後端要 rationale
        "recommended_action": decision.recommended_action,
        "policy_violation": (
            decision.policy_violation.value
            if decision.policy_violation is not None else None
        ),
    }


def from_backend_response(resp: dict) -> dict:
    """把後端 /tool/call 的 Response 收斂成本模組好用的 dict。

    後端良性時 attack_type 是 "none";若回 null 也容錯成 "none"。
    """
    attack = resp.get("attack_type") or "none"
    return {
        "decision": resp.get("decision"),
        "risk_level": resp.get("risk_level"),
        "attack_type": attack,
        "intent_match": resp.get("intent_match"),
        "evidence": resp.get("evidence"),
        "rationale": resp.get("rationale"),
        "recommended_action": resp.get("recommended_action"),
        "policy_violation": resp.get("policy_violation"),
        "tool_output": resp.get("tool_output"),  # 僅 allow 時有值
    }