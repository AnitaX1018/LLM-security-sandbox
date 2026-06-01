"""
case.py — 「輸入契約」:Policy Engine 每次收到的一個待審查案例。

對應 schema.py(輸出契約)。一個案例 = LLM 要看的所有資訊。
這個結構同時也是你 200 筆資料集每一筆的格式。
"""

from typing import Optional

from pydantic import BaseModel, Field

from policy_engine.schema import Decision


class ToolCall(BaseModel):
    """agent 想執行的單一工具呼叫。"""
    name: str                                   # 例如 "send_email"
    args: dict = Field(default_factory=dict)    # 例如 {"to": "x@y.com"}


class HistoryItem(BaseModel):
    """session 歷史中的一筆:之前的某次 tool call 與當時的裁決。"""
    tool_call: ToolCall
    decision: Decision


class ToolCallCase(BaseModel):
    """一個完整的待審查案例(也是資料集每一筆的格式)。"""

    user_message: str = Field(
        ..., description="使用者原始說的話(他的真實意圖來源)"
    )
    external_content: Optional[str] = Field(
        default=None,
        description="agent 讀進來的外部內容;indirect injection 藏在這裡",
    )
    tool_call: ToolCall = Field(
        ..., description="現在這一刻 agent 想執行的工具呼叫"
    )
    session_history: list[HistoryItem] = Field(
        default_factory=list,
        description="本 session 之前已執行的 tool call(L3 行為鏈分析用)",
    )