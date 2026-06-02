"""
格式：
  data/api_cases.jsonl     輸入欄位（tool_name / parameters / user_prompt / agent_context）
  data/ground_truth.jsonl  標籤欄位（expected_decision / expected_attack_type_backend ...）

兩個檔案以 case_id 對應。

關鍵設計：session_group
  多輪攻擊用 session_group 標記。例如：
      ESCALATION_001_R1   group: ESCALATION_001
      ESCALATION_001_R2   group: ESCALATION_001
      ESCALATION_001_R3   group: ESCALATION_001
  我們依出現順序，把同 group 內「先前的案例」放進當前案例的 session_history，
  L3 行為鏈分析才能看到上下文。

使用方式：
    from data.dataset_loader import load_dataset
    cases = load_dataset()  # 預設讀 data/ 下的兩個檔案
"""

import json
from pathlib import Path
from typing import Optional

from policy_engine.case import ToolCall, ToolCallCase, HistoryItem
from policy_engine.schema import Decision


def _load_jsonl(path: Path) -> list[dict]:
    """讀一個 JSONL 檔案，每行一個 dict。"""
    if not path.exists():
        raise FileNotFoundError(f"找不到檔案：{path}")
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def load_dataset(
    cases_path: str | Path | None = None,
    ground_truth_path: str | Path | None = None,
    max_cases: Optional[int] = None,
) -> list[tuple[ToolCallCase, Decision]]:
    """載入資料集，回傳 (ToolCallCase, expected_decision) 列表。

    Args:
        cases_path        : api_cases.jsonl 路徑，預設 data/api_cases.jsonl
        ground_truth_path : ground_truth.jsonl 路徑，預設 data/ground_truth.jsonl
        max_cases         : 只載入前 N 筆（測試用）

    Returns:
        list of (ToolCallCase, expected_decision)，
        可以直接傳給 evaluation/evaluate.py 的 run_evaluation()。
    """
    data_dir = Path(__file__).resolve().parent
    cases_path = Path(cases_path) if cases_path else data_dir / "api_cases.jsonl"
    ground_truth_path = (Path(ground_truth_path) if ground_truth_path
                         else data_dir / "ground_truth.jsonl")

    raw_cases = _load_jsonl(cases_path)
    raw_truths = _load_jsonl(ground_truth_path)

    # 把 ground truth 建成 case_id -> 標籤 的字典，方便查找
    truth_map = {item["case_id"]: item for item in raw_truths}

    # 同 session_group 內，累積已出現的 (ToolCall, Decision) 當作後續案例的歷史
    group_history: dict[str, list[HistoryItem]] = {}

    results = []
    for raw in raw_cases:
        case_id = raw["case_id"]
        truth = truth_map.get(case_id)
        if truth is None:
            continue  # 沒有 ground truth 就跳過

        # 組裝 tool_call（新格式直接就是 tool_name + parameters）
        tool_call = ToolCall(name=raw["tool_name"], args=raw.get("parameters", {}))

        # 取本 session_group 在這一筆之前累積的歷史
        group = raw["session_group"]
        history_so_far = list(group_history.get(group, []))

        case = ToolCallCase(
            user_message=raw["user_prompt"],
            external_content=raw.get("agent_context") or None,
            tool_call=tool_call,
            session_history=history_so_far,
        )

        expected = Decision(truth["expected_decision"])
        results.append((case, expected))

        # 把這一筆加入該 group 的歷史，供同 group 的下一筆使用
        group_history.setdefault(group, []).append(
            HistoryItem(tool_call=tool_call, decision=expected)
        )

        if max_cases and len(results) >= max_cases:
            break

    return results


def dataset_stats(cases: list[tuple[ToolCallCase, Decision]]) -> None:
    """印出資料集的分佈摘要。"""
    from collections import Counter
    dist = Counter(d.value for _, d in cases)
    total = len(cases)
    has_history = sum(1 for c, _ in cases if c.session_history)
    print(f"資料集共 {total} 筆，其中 {has_history} 筆帶 session 歷史")
    for label, count in sorted(dist.items()):
        print(f"  {label:<25} {count:>4} 筆 ({count/total*100:.1f}%)")


if __name__ == "__main__":
    cases = load_dataset()
    print(f"成功載入 {len(cases)} 筆\n")
    print("── 前 3 筆預覽 ──")
    for case, decision in cases[:3]:
        print(f"[{decision.value:22s}] {case.user_message[:50]}")
        print(f"   tool: {case.tool_call.name}  history: {len(case.session_history)} 筆")
    print()
    print("── 全量統計 ──")
    dataset_stats(cases)