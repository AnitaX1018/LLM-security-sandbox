# Agent Security Sandbox — Prompt Engineering 模組

負責人：蕭任芮 R14525076 ｜ Group 128

Policy Engine 的 Prompt Engineering 子系統。目標：讓 LLM 在每次 tool call 執行前，
扮演「Security Policy Auditor」，判斷該操作是否安全。

## 架構（Hybrid Rule + LLM）

```
Tool Call Request
      │
      ▼
 L1 Input Scan (LLM)        ← 偵測直接注入 / 明顯攻擊
      │ block? → 提前結束
      ▼
 L2 Intent Consistency (LLM) ← 意圖偏離 / 身份偽裝
      │ block? → 提前結束
      ▼
 Rule Analyzer              ← 確定性升級分數（外洩鏈、破壞性查詢）
      │
      ▼
 L3 Behavioral Chain (LLM)  ← LLM 看規則分析 + session 歷史做最終裁決
      │
      ▼
 PolicyDecision（最嚴格那層）
```

## 資料夾結構

```
agent_security_sandbox/
├── policy_engine/
│   ├── schema.py            ← 結構化輸出契約（8 欄位，Pydantic v2）
│   ├── case.py              ← 輸入契約（待審案例 / 資料集格式）
│   ├── rule_analyzer.py     ← L3 確定性規則層（升級分數計算）
│   ├── system_prompt.py     ← 四區塊 System Prompt（含 risk level 閾值）
│   ├── few_shot.py          ← Few-shot 範例庫（16 例）
│   ├── prompts.py           ← 三層 Prompt 組裝（含 zero/few-shot 開關）
│   ├── llm_client.py        ← MockLLM / GroqLLMClient / OllamaLLMClient
│   ├── engine.py            ← 三層 Pipeline 串接（Hybrid Rule + LLM）
│   └── backend_adapter.py   ← 本模組格式 <-> 後端 API 格式
├── data/
│   ├── api_cases.jsonl      ← 組員 B 的 200 筆測試案例（輸入）
│   ├── ground_truth.jsonl   ← 組員 B 的 200 筆 ground truth 標籤
│   └── dataset_loader.py    ← 載入資料集（回傳 decision+risk_level+attack_type）
├── evaluation/
│   └── evaluate.py          ← zero-shot vs few-shot 評估（三欄位比對）
└── tests/
    ├── test_schema.py        ← 4 個測試
    ├── test_engine.py        ← 8 個測試（含 rule_analyzer）
    ├── test_prompts.py       ← 7 個測試
    └── test_backend_connection.py ← 後端串接測試
```

## 快速開始

```bash
# 安裝
pip install pydantic

# 本機測試（離線，不需 glows.ai）
PYTHONPATH=. python3 tests/test_schema.py
PYTHONPATH=. python3 tests/test_engine.py
PYTHONPATH=. python3 tests/test_prompts.py

# 後端串接測試（填入組員 A 的網址後）
# BACKEND_URL = "https://..." 填入 tests/test_backend_connection.py
PYTHONPATH=. python3 tests/test_backend_connection.py

# 完整評估（需在 glows.ai img-neqm8dp2 上跑）
PYTHONPATH=. python3 evaluation/evaluate.py
```

## 評估結果（gpt-oss:20b，200 筆）

| 指標 | Zero-shot | Few-shot | 改善 |
|---|---|---|---|
| Precision | 0.9792 | 0.9722 | -0.007 |
| Recall | 0.8545 | 0.9545 | **+0.100** |
| F1 | 0.9126 | 0.9633 | **+0.051** |
| FPR | 0.0222 | 0.0333 | +0.011 |
| ASR | 0.1455 | 0.0455 | **-0.100** |
| Risk Level Acc. | 0.4950 | 0.5950 | +0.100 |
| Attack Type Acc. | 0.8450 | 0.9300 | +0.085 |

Few-shot 在 Recall 和 F1 顯著提升，ASR 從 14.5% 降至 4.5%。
兩次評估 F1 差異在 0.05 以內，顯示 pipeline 穩定。

## 後端串接（組員 A）

```python
from policy_engine.backend_adapter import to_tool_call_request
request_body = to_tool_call_request(case, session_id="your-session-id")
# → {"session_id":..., "tool_name":..., "parameters":..., "user_prompt":..., "agent_context":""}
```

## 評估整合（組員 D）

```python
from data.dataset_loader import load_dataset
cases = load_dataset()  # list of (ToolCallCase, {"decision":..., "risk_level":..., "attack_type":...})
```

## 在 glows.ai 上執行

```bash
# 開機選 img-neqm8dp2（已有 gpt-oss:20b）
git clone https://github.com/AnitaX1018/LLM-security-sandbox.git
cd LLM-security-sandbox
pip install pydantic
PYTHONPATH=. python3 evaluation/evaluate.py
```