"""
engine.py — 三層 Policy Pipeline 串接

流程：
  L1 Input Scan         → 偵測明顯注入，若 block 提前結束
  L2 Intent Consistency → 偵測意圖偏離與身份偽裝，若 block 提前結束
  L3 Behavioral Chain   → 偵測多輪攻擊鏈
  最終裁決 = 三層中最嚴格的那個（block > require_confirmation > allow）
"""

from policy_engine.case import ToolCallCase
from policy_engine.schema import PolicyDecision, Decision
from policy_engine.prompts import build_messages
from policy_engine.llm_client import BaseLLMClient, call_with_retry

SEVERITY = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_CONFIRMATION: 1,
    Decision.BLOCK: 2,
}

LAYERS = ["input_scan", "intent_consistency", "behavioral_chain"]


class PolicyEngine:
    """三層 Policy Engine。

    使用範例:
        engine = PolicyEngine(MockLLMClient(), use_few_shot=True)
        result = engine.evaluate(case)
        print(result.decision.value)
    """

    def __init__(self, llm_client: BaseLLMClient, use_few_shot: bool = True):
        """
        Args:
            llm_client : LLM 客戶端（Mock 或真實）
            use_few_shot: True=few-shot / False=zero-shot（RQ1 對照開關）
        """
        self.client = llm_client
        self.use_few_shot = use_few_shot

    def evaluate(self, case: ToolCallCase) -> PolicyDecision:
        """對一個案例跑完三層審查，回傳最終裁決。"""

        results: dict[str, PolicyDecision] = {}

        for layer in LAYERS:
            print(f"  → 執行 {layer}...")
            messages = build_messages(case, layer=layer, use_few_shot=self.use_few_shot)
            decision = call_with_retry(self.client, messages)
            results[layer] = decision

            # Early exit：已確定是攻擊，後面的層不需要再跑
            if decision.decision == Decision.BLOCK:
                print(f"    block — 提前結束")
                break

        # 回傳三層中最嚴格的裁決
        return max(results.values(), key=lambda d: SEVERITY[d.decision])
