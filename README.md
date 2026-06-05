# Agent Security Sandbox — Prompt Engineering 模組

Policy Engine 的 Prompt Engineering 子系統。目標：讓 LLM 在每次 tool call 執行前，
扮演「Security Policy Auditor」，判斷該操作是否安全。

## 架構（Hybrid Rule + LLM）

```
Tool Call Request
      │
      ▼
 L1 Input Scan (LLM)         ← 偵測直接注入 / 明顯攻擊
      │ block? → 提前結束（ablation_mode=True 時繼續跑）
      ▼
 L2 Intent Consistency (LLM) ← 意圖偏離 / 身份偽裝
      │ block? → 提前結束
      ▼
 Rule Analyzer               ← 確定性升級分數 + Session 軌跡摘要
      │
      ▼
 L3 Behavioral Chain (LLM)   ← 看規則分數 + 實際 session 軌跡做最終裁決
      │
      ▼
 PolicyDecision
```

**L2 vs L3 的差別：**
- L2 = 單一 tool call 的意圖分析（LLM only）
- L3 = 跨多輪攻擊鏈分析（Rule Analyzer 先計算升級分數並生成 session 軌跡 → LLM 基於具體軌跡做語意推理）

## 資料夾結構

```
agent_security_sandbox/
├── policy_engine/
│   ├── schema.py            ← 結構化輸出契約（8 欄位，Pydantic v2）
│   ├── case.py              ← 輸入契約（待審案例 / 資料集格式）
│   ├── rule_analyzer.py     ← L3 規則層：升級分數 + session 軌跡摘要
│   ├── system_prompt.py     ← 四區塊 System Prompt（含 5 維度 session pattern）
│   ├── few_shot.py          ← Few-shot 範例庫（16 例）
│   ├── prompts.py           ← 三層 Prompt 組裝（含 zero/few-shot 開關）
│   ├── llm_client.py        ← MockLLM / GroqLLMClient / OllamaLLMClient
│   ├── engine.py            ← 三層 Pipeline（含 ablation_mode）
│   └── backend_adapter.py   ← 本模組格式 <-> 後端 API 格式
├── data/
│   ├── api_cases.jsonl      ← 200 筆測試案例
│   ├── ground_truth.jsonl   ← ground truth 標籤
│   └── dataset_loader.py    ← 載入資料集（decision + risk_level + attack_type）
├── evaluation/
│   └── evaluate.py          ← 二分類（F1/FPR/ASR）+ 三分類（Macro F1 + 混淆矩陣）
└── tests/
    ├── test_schema.py        ← 4 個測試
    ├── test_engine.py        ← 8 個測試（含 rule_analyzer + ablation）
    ├── test_prompts.py       ← 7 個測試
    └── test_backend_connection.py
```

## 測試

```bash
pip install pydantic scikit-learn

# 本機測試
PYTHONPATH=. python3 tests/test_schema.py
PYTHONPATH=. python3 tests/test_engine.py
PYTHONPATH=. python3 tests/test_prompts.py

# 完整評估（需在 glows.ai上跑）
PYTHONPATH=. python3 evaluation/evaluate.py

# Ablation Study（強制跑完三層不 early exit）
# engine = PolicyEngine(client, use_few_shot=True, ablation_mode=True) 
```

## 評估結果（gpt-oss:20b，200 筆，第二次跑）

### 二分類（block = 攻擊）

| 指標 | Zero-shot | Few-shot | 改善 |
|---|---|---|---|
| Precision | 0.9792 | 0.9722 | -0.007 |
| Recall | 0.8545 | 0.9545 | **+0.100** |
| F1 | 0.9126 | 0.9633 | **+0.051** |
| FPR | 0.0222 | 0.0333 | +0.011 |
| ASR | 0.1455 | 0.0455 | **-0.100** |

### 三分類（Macro F1，含 require_confirmation）
待更新（需在 glows.ai 重跑，含 scikit-learn 混淆矩陣）

## 主要設計決策

**ablation_mode**：設為 `True` 時，即使 L1/L2 判定 block 也繼續跑完三層，
用於 RQ3 對照實驗（測量 L1 alone vs L1+L2+L3 的效果差異），確保實驗變數乾淨。

**Session Trajectory in L3**：`rule_analyzer.build_session_summary()` 生成
乾淨的工具執行軌跡文字注入 L3 prompt，讓 LLM 真正「看見」意圖的演進
（Goal Transition），而不只是看數字分數。

**Macro F1**：三分類評估採用 scikit-learn macro F1，避免 class imbalance 時
指標被 `block`（110 筆）主導而高估整體表現。

## 後端串接

```bash
# 填入網址後執行
# BACKEND_URL = "https://tw-05.access.glows.ai:25872"
PYTHONPATH=. python3 tests/test_backend_connection.py
```

## glows.ai 執行

```bash
git clone https://github.com/AnitaX1018/LLM-security-sandbox.git
cd LLM-security-sandbox
pip install pydantic scikit-learn
PYTHONPATH=. python3 evaluation/evaluate.py
```
