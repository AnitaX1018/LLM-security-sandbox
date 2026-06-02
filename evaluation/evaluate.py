"""
evaluate.py — Step 6：zero-shot vs few-shot 評估，回答 Sub RQ1

執行方式：
    cd agent-security-sandbox
    PYTHONPATH=. python3 evaluation/evaluate.py

輸出：
  - 每筆案例的預測 vs 正確答案
  - zero-shot 與 few-shot 的 Precision / Recall / F1 / FPR / ASR 比較表

評估指標定義（對齊後端 API 文件）：
  TP  攻擊案例被正確封鎖
  FP  良性案例被誤判封鎖（誤攔）
  TN  良性案例被正確放行
  FN  攻擊案例被漏放（漏攔）

  Precision = TP / (TP + FP)     → 封鎖裁決中真的是攻擊的比例
  Recall    = TP / (TP + FN)     → 所有攻擊中被正確封鎖的比例
  F1        = 調和平均數
  FPR       = FP / (FP + TN)     → 良性請求被誤攔的比例（越低越好）
  ASR       = FN / (TP + FN)     → 攻擊成功率（越低越好）
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy_engine.llm_client import MockLLMClient
from policy_engine.engine import PolicyEngine
from policy_engine.schema import Decision
from data.dataset_loader import load_dataset

# 自動讀取 data/api_cases.jsonl + data/ground_truth.jsonl（B 的 v2 格式）
TEST_CASES = load_dataset()
print(f"已載入資料集：{len(TEST_CASES)} 筆")


def is_attack(decision: Decision) -> bool:
    """把三值裁決對應到「是否為攻擊」的二元標籤。
    block = 攻擊；allow / require_confirmation = 非攻擊。
    """
    return decision == Decision.BLOCK


def compute_metrics(results: list[tuple[Decision, Decision]]) -> dict:
    """計算評估指標。

    Args:
        results: list of (predicted, expected)
    """
    TP = FP = TN = FN = 0

    for predicted, expected in results:
        pred_attack = is_attack(predicted)
        true_attack = is_attack(expected)

        if pred_attack and true_attack:
            TP += 1
        elif pred_attack and not true_attack:
            FP += 1
        elif not pred_attack and not true_attack:
            TN += 1
        else:
            FN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    asr       = FN / (TP + FN) if (TP + FN) > 0 else 0.0

    return {
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "Precision": precision,
        "Recall":    recall,
        "F1":        f1,
        "FPR":       fpr,
        "ASR":       asr,
    }


def run_evaluation(use_few_shot: bool) -> list[tuple[Decision, Decision]]:
    """跑完所有測試案例，回傳 (預測, 正確答案) 的列表。"""
    mode = "few-shot" if use_few_shot else "zero-shot"
    print(f"\n{'='*55}")
    print(f"執行 {mode} 評估（共 {len(TEST_CASES)} 筆）")
    print(f"{'='*55}")

    engine = PolicyEngine(MockLLMClient(), use_few_shot=use_few_shot)
    results = []

    for i, (case, expected) in enumerate(TEST_CASES, 1):
        print(f"\n[{i:02d}] {case.user_message[:45]}...")
        predicted = engine.evaluate(case)

        correct = "✓" if predicted.decision == expected else "✗"
        print(f"     預測: {predicted.decision.value:22s} | 正確: {expected.value:22s} {correct}")
        results.append((predicted.decision, expected))

    return results


def print_metrics_table(zero_metrics: dict, few_metrics: dict) -> None:
    """並排印出兩種模式的指標比較表。"""
    print(f"\n{'='*55}")
    print("評估結果比較（Sub RQ1）")
    print(f"{'='*55}")
    print(f"{'指標':<12} {'Zero-shot':>12} {'Few-shot':>12} {'差異':>10}")
    print("-" * 50)

    pct_metrics = ["Precision", "Recall", "F1", "FPR", "ASR"]
    for key in pct_metrics:
        z = zero_metrics[key]
        f = few_metrics[key]
        diff = f - z
        arrow = "↑" if diff > 0 else ("↓" if diff < 0 else "─")
        # F1/Recall 越高越好；FPR/ASR 越低越好
        good = (key in ("F1", "Precision", "Recall") and diff >= 0) or \
               (key in ("FPR", "ASR") and diff <= 0)
        marker = "✓" if good and diff != 0 else ""
        print(f"  {key:<10} {z:>11.4f} {f:>11.4f}   {arrow}{abs(diff):.4f} {marker}")

    print("-" * 50)
    print(f"  {'TP':<10} {zero_metrics['TP']:>11} {few_metrics['TP']:>11}")
    print(f"  {'FP':<10} {zero_metrics['FP']:>11} {few_metrics['FP']:>11}")
    print(f"  {'TN':<10} {zero_metrics['TN']:>11} {few_metrics['TN']:>11}")
    print(f"  {'FN':<10} {zero_metrics['FN']:>11} {few_metrics['FN']:>11}")
    print(f"{'='*55}")

    # RQ1 結論
    print("\nSub RQ1 初步結論：")
    if few_metrics["F1"] > zero_metrics["F1"] and few_metrics["FPR"] <= zero_metrics["FPR"]:
        print("  Few-shot 在 F1 提升的同時 FPR 未上升 → 假設成立 ✓")
    elif few_metrics["F1"] > zero_metrics["F1"]:
        print("  Few-shot F1 較高，但 FPR 也略有上升 → 存在 precision-recall 取捨")
    elif few_metrics["F1"] == zero_metrics["F1"]:
        print("  兩者 F1 相同（MockLLM 不受 few-shot 影響）")
        print("  → 換成真實 LLM 後才能看出差異，此為預期行為")
    else:
        print("  Few-shot 效果不如 zero-shot → 需檢查範例品質")


if __name__ == "__main__":
    zero_results = run_evaluation(use_few_shot=False)
    few_results  = run_evaluation(use_few_shot=True)

    zero_metrics = compute_metrics(zero_results)
    few_metrics  = compute_metrics(few_results)

    print_metrics_table(zero_metrics, few_metrics)