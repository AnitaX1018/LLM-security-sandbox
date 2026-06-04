"""
回傳格式：list of (ToolCallCase, dict)
  dict 包含三個 ground truth 欄位：
    - decision   : Decision（allow / require_confirmation / block）
    - risk_level : str（low / medium / high / critical）
    - attack_type: str（none / prompt_injection / data_exfiltration / destructive_action）
"""

import json
from pathlib import Path
from typing import Optional

from policy_engine.case import ToolCall, ToolCallCase, HistoryItem
from policy_engine.schema import Decision


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"找不到檔案：{path}")
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def _parse_history(raw_history: list[str]) -> list[HistoryItem]:
    items = []
    for entry in raw_history:
        try:
            if "->" in entry:
                left, right = entry.rsplit("->", 1)
                tool_name = left.strip().split()[0]
                decision_str = right.strip().lower()
                if decision_str in ("allow", "require_confirmation", "block"):
                    items.append(HistoryItem(
                        tool_call=ToolCall(name=tool_name, args={}),
                        decision=Decision(decision_str),
                    ))
        except Exception:
            continue
    return items


def load_dataset(
    cases_path: str | Path | None = None,
    ground_truth_path: str | Path | None = None,
    max_cases: Optional[int] = None,
) -> list[tuple[ToolCallCase, dict]]:
    """載入 B 的 v2 資料集。

    Returns:
        list of (ToolCallCase, ground_truth_dict)
        ground_truth_dict 有三個 key：
            decision   : Decision
            risk_level : str
            attack_type: str（backend 版，對齊 schema）
    """
    data_dir = Path(__file__).resolve().parent
    cases_path = Path(cases_path) if cases_path else data_dir / "api_cases.jsonl"
    ground_truth_path = (Path(ground_truth_path) if ground_truth_path
                         else data_dir / "ground_truth.jsonl")

    raw_cases = _load_jsonl(cases_path)
    raw_truths = _load_jsonl(ground_truth_path)
    truth_map = {item["case_id"]: item for item in raw_truths}

    group_history: dict[str, list[HistoryItem]] = {}
    results = []

    for raw in raw_cases:
        case_id = raw["case_id"]
        truth = truth_map.get(case_id)
        if truth is None:
            continue

        tool_call = ToolCall(name=raw["tool_name"], args=raw.get("parameters", {}))
        group = raw["session_group"]
        history_so_far = list(group_history.get(group, []))

        case = ToolCallCase(
            user_message=raw["user_prompt"],
            external_content=raw.get("agent_context") or None,
            tool_call=tool_call,
            session_history=history_so_far,
        )

        gt = {
            "decision":    Decision(truth["expected_decision"]),
            "risk_level":  truth["expected_risk_level_dataset"],
            "attack_type": truth["expected_attack_type_backend"],
        }

        results.append((case, gt))
        group_history.setdefault(group, []).append(
            HistoryItem(tool_call=tool_call, decision=gt["decision"])
        )

        if max_cases and len(results) >= max_cases:
            break

    return results


def dataset_stats(cases: list[tuple[ToolCallCase, dict]]) -> None:
    from collections import Counter
    dist = Counter(gt["decision"].value for _, gt in cases)
    total = len(cases)
    has_history = sum(1 for c, _ in cases if c.session_history)
    print(f"資料集共 {total} 筆，其中 {has_history} 筆帶 session 歷史")
    for label, count in sorted(dist.items()):
        print(f"  {label:<25} {count:>4} 筆 ({count/total*100:.1f}%)")