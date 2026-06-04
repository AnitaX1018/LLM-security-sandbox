"""
zero-shot vs few-shot 評估，回答 Sub RQ1

比對三個欄位：
  decision    → 主指標（F1 / Precision / Recall / FPR / ASR）
  risk_level  → 輔助指標（準確率）
  attack_type → 輔助指標（準確率）
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collections import Counter
from policy_engine.llm_client import OllamaLLMClient
from policy_engine.engine import PolicyEngine
from policy_engine.schema import Decision
from data.dataset_loader import load_dataset

TEST_CASES = load_dataset()
print(f"已載入資料集：{len(TEST_CASES)} 筆")


# ── 指標計算 ─────────────────────────────────────────────────────

def is_attack(d: Decision) -> bool:
    return d == Decision.BLOCK


def compute_decision_metrics(results: list[tuple[Decision, Decision]]) -> dict:
    """二元 F1 指標（block = 攻擊）。"""
    TP = FP = TN = FN = 0
    for pred, exp in results:
        pa, ta = is_attack(pred), is_attack(exp)
        if pa and ta:     TP += 1
        elif pa and not ta: FP += 1
        elif not pa and not ta: TN += 1
        else:              FN += 1
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1  = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    asr = FN / (TP + FN) if (TP + FN) > 0 else 0.0
    return {"TP":TP,"FP":FP,"TN":TN,"FN":FN,
            "Precision":precision,"Recall":recall,"F1":f1,"FPR":fpr,"ASR":asr}


def compute_accuracy(pairs: list[tuple[str, str]]) -> float:
    """完全一致的準確率。"""
    return sum(1 for p, e in pairs if p == e) / len(pairs) if pairs else 0.0


# ── 評估執行 ─────────────────────────────────────────────────────

def run_evaluation(use_few_shot: bool):
    mode = "few-shot" if use_few_shot else "zero-shot"
    print(f"\n{'='*55}")
    print(f"執行 {mode} 評估（共 {len(TEST_CASES)} 筆）")
    print(f"{'='*55}")

    engine = PolicyEngine(OllamaLLMClient(model="gpt-oss:20b"), use_few_shot=use_few_shot)

    decision_pairs = []
    risk_pairs     = []
    attack_pairs   = []

    for i, (case, gt) in enumerate(TEST_CASES, 1):
        print(f"\n[{i:03d}] {case.user_message[:45]}...")
        predicted = engine.evaluate(case)

        d_ok = "✓" if predicted.decision == gt["decision"] else "✗"
        r_ok = "✓" if predicted.risk_level.value == gt["risk_level"] else "✗"
        a_ok = "✓" if predicted.attack_type.value == gt["attack_type"] else "✗"

        print(f"  decision    {predicted.decision.value:22s} | {gt['decision'].value:22s} {d_ok}")
        print(f"  risk_level  {predicted.risk_level.value:22s} | {gt['risk_level']:22s} {r_ok}")
        print(f"  attack_type {predicted.attack_type.value:22s} | {gt['attack_type']:22s} {a_ok}")

        decision_pairs.append((predicted.decision,       gt["decision"]))
        risk_pairs.append((predicted.risk_level.value,   gt["risk_level"]))
        attack_pairs.append((predicted.attack_type.value, gt["attack_type"]))

    return decision_pairs, risk_pairs, attack_pairs


# ── 輸出比較表 ───────────────────────────────────────────────────

def print_results(zero, few):
    z_dec, z_risk, z_atk = zero
    f_dec, f_risk, f_atk = few

    z_m = compute_decision_metrics(z_dec)
    f_m = compute_decision_metrics(f_dec)

    print(f"\n{'='*60}")
    print("評估結果比較（Sub RQ1）")
    print(f"{'='*60}")

    # Decision 指標
    print(f"\n── Decision（主指標）{'─'*36}")
    print(f"{'指標':<12} {'Zero-shot':>12} {'Few-shot':>12} {'差異':>10}")
    print("-" * 50)
    for key in ["Precision","Recall","F1","FPR","ASR"]:
        z, f = z_m[key], f_m[key]
        diff = f - z
        arrow = "↑" if diff > 0 else ("↓" if diff < 0 else "─")
        good = (key in ("F1","Precision","Recall") and diff >= 0) or \
               (key in ("FPR","ASR") and diff <= 0)
        mark = "✓" if good and diff != 0 else ""
        print(f"  {key:<10} {z:>11.4f} {f:>11.4f}   {arrow}{abs(diff):.4f} {mark}")
    print("-" * 50)
    print(f"  {'TP':<10} {z_m['TP']:>11} {f_m['TP']:>11}")
    print(f"  {'FP':<10} {z_m['FP']:>11} {f_m['FP']:>11}")
    print(f"  {'TN':<10} {z_m['TN']:>11} {f_m['TN']:>11}")
    print(f"  {'FN':<10} {z_m['FN']:>11} {f_m['FN']:>11}")

    # Risk level 準確率
    z_racc = compute_accuracy(z_risk)
    f_racc = compute_accuracy(f_risk)
    print(f"\n── Risk Level 準確率（輔助指標）{'─'*22}")
    print(f"  Zero-shot: {z_racc:.4f}   Few-shot: {f_racc:.4f}   差異: {f_racc-z_racc:+.4f}")
    # 各等級的預測分布
    for mode_name, pairs in [("Zero", z_risk), ("Few ", f_risk)]:
        dist = Counter(p for p, _ in pairs)
        print(f"  {mode_name} 預測分布: " + "  ".join(f"{k}:{v}" for k, v in sorted(dist.items())))

    # Attack type 準確率
    z_aacc = compute_accuracy(z_atk)
    f_aacc = compute_accuracy(f_atk)
    print(f"\n── Attack Type 準確率（輔助指標）{'─'*21}")
    print(f"  Zero-shot: {z_aacc:.4f}   Few-shot: {f_aacc:.4f}   差異: {f_aacc-z_aacc:+.4f}")
    for mode_name, pairs in [("Zero", z_atk), ("Few ", f_atk)]:
        dist = Counter(p for p, _ in pairs)
        print(f"  {mode_name} 預測分布: " + "  ".join(f"{k}:{v}" for k, v in sorted(dist.items())))

    print(f"\n{'='*60}")
    # RQ1 結論
    if f_m["F1"] > z_m["F1"] and f_m["FPR"] <= z_m["FPR"]:
        print("Sub RQ1：Few-shot F1 提升且 FPR 未上升 → 假設成立 ✓")
    elif f_m["F1"] > z_m["F1"]:
        print("Sub RQ1：Few-shot F1 較高，但 FPR 略有上升")
    else:
        print("Sub RQ1：兩者相近，需進一步分析")


if __name__ == "__main__":
    zero = run_evaluation(use_few_shot=False)
    few  = run_evaluation(use_few_shot=True)
    print_results(zero, few)