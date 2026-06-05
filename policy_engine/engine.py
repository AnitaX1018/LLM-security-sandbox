"""
engine.py — 三層 Policy Pipeline 串接

架構（Hybrid Rule + LLM）：
  L1 Input Scan         → LLM：偵測明顯注入，若 block 提前結束
  L2 Intent Consistency → LLM：偵測意圖偏離與身份偽裝，若 block 提前結束
  L3 Behavioral Chain   → Rule Analyzer 先算升級分數 → LLM 做最終裁決

L3 與 L2 的差別：
  L2 = 單一 tool call 的意圖分析
  L3 = 跨多輪的攻擊鏈模式（先用確定性規則評分，再交給 LLM 解釋）

最終裁決 = 三層中最嚴格的那個（block > require_confirmation > allow）
"""

import logging

from policy_engine.case import ToolCallCase
from policy_engine.schema import PolicyDecision, Decision
from policy_engine.prompts import build_messages
from policy_engine.llm_client import BaseLLMClient, call_with_retry
from policy_engine.rule_analyzer import analyze_behavior

logger = logging.getLogger(__name__)

SEVERITY = {
    Decision.ALLOW: 0,
    Decision.REQUIRE_CONFIRMATION: 1,
    Decision.BLOCK: 2,
}

LAYERS = ["input_scan", "intent_consistency", "behavioral_chain"]


class PolicyEngine:
    """三層 Policy Engine（Hybrid Rule + LLM）。

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
            logger.info("執行 %s", layer)
            print(f"  → 執行 {layer}...")

            if layer == "behavioral_chain":
                # L3 專屬：先執行確定性規則分析，注入升級分數
                analysis = analyze_behavior(case)
                logger.info(
                    "Behavioral analysis: score=%d, patterns=%s",
                    analysis.escalation_score,
                    analysis.patterns_detected,
                )
                messages = build_messages(
                    case, layer=layer,
                    use_few_shot=self.use_few_shot,
                    extra_context=analysis.to_prompt_block(),
                )
            else:
                messages = build_messages(
                    case, layer=layer,
                    use_few_shot=self.use_few_shot,
                )

            decision = call_with_retry(self.client, messages)
            results[layer] = decision

            if decision.decision == Decision.BLOCK:
                logger.info("Layer %s returned block — early exit", layer)
                print(f"    block — 提前結束")
                break

        return max(results.values(), key=lambda d: SEVERITY[d.decision])
