# Agent Security Sandbox — Policy Engine 完整實作

Agent Security Sandbox 的 Policy Engine 完整實作，包含 LLM 三層審查 Pipeline、
Hybrid Rule + LLM 行為鏈分析、Few-shot Prompt Engineering 及評估框架。

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
 PolicyDecision（最嚴格那層）
```

**L2 vs L3：**
- L2 = 單一 tool call 的意圖分析（LLM only）
- L3 = 跨多輪攻擊鏈分析（Rule Analyzer 先計算升級分數並生成 session 軌跡 → LLM 基於具體軌跡做語意推理）

## 資料夾結構

```
agent_security_sandbox/
├── policy_engine/
│   ├── schema.py            ← 結構化輸出契約（8 欄位，Pydantic v2）
│   ├── case.py              ← 輸入契約
│   ├── rule_analyzer.py     ← L3 規則層：升級分數 + session 軌跡摘要
│   ├── system_prompt.py     ← 四區塊 System Prompt（含 5 維度 session pattern）
│   ├── few_shot.py          ← Few-shot 範例庫（16 例）
│   ├── prompts.py           ← 三層 Prompt 組裝（含 zero/few-shot 及 ablation 開關）
│   ├── llm_client.py        ← MockLLM / GroqLLMClient / OllamaLLMClient
│   ├── engine.py            ← 三層 Pipeline（含 ablation_mode）
│   └── backend_adapter.py   ← 本模組格式 <-> 後端 API 格式
├── data/
│   ├── api_cases.jsonl      ← 組員 B 的 200 筆測試案例
│   ├── ground_truth.jsonl   ← 組員 B 的 ground truth 標籤
│   └── dataset_loader.py    ← 載入資料集（decision + risk_level + attack_type）
├── evaluation/
│   └── evaluate.py          ← 二分類（F1/FPR/ASR）+ 三分類（Macro F1 + 混淆矩陣）+ 各攻擊類型召回率
└── tests/
    ├── test_schema.py        ← 4 個測試
    ├── test_engine.py        ← 8 個測試（含 rule_analyzer + escalation）
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
export PYTHONPATH=.
nohup python3 evaluation/evaluate.py > eval_output.txt 2>&1 &

# Ablation Study（強制跑完三層）
# engine = PolicyEngine(client, use_few_shot=True, ablation_mode=True)
```

## 最終評估結果（gpt-oss:20b，200 筆）

### 二分類（block = 攻擊）

| 指標 | Zero-shot | Few-shot | 改善 |
|---|---|---|---|
| Precision | 0.9880 | 0.9817 | -0.006 |
| Recall | 0.7455 | **0.9727** | **+0.227** |
| F1 | 0.8497 | **0.9772** | **+0.127** |
| FPR | 0.0111 | 0.0222 | +0.011 |
| ASR | 0.2545 | **0.0273** | **-0.227** |

### 三分類（Macro F1，含 require_confirmation）

| 指標 | Zero-shot | Few-shot | 改善 |
|---|---|---|---|
| Accuracy | 0.8200 | **0.9450** | +0.125 |
| Macro F1 | 0.7966 | **0.9187** | **+0.122** |

### 核心發現：Zero-shot 的主要弱點

混淆矩陣顯示 zero-shot 將 **28 個攻擊案例誤判為 require_confirmation**（而非 block）。
Few-shot 將此數字降至 **3 筆**，這是召回率大幅提升的主要原因。

```
Zero-shot:  true:block | pred:require_confirmation = 28 筆  (ASR 25.5%)
Few-shot:   true:block | pred:require_confirmation =  3 筆  (ASR  2.7%)
```

require_confirmation 的 F1 從 0.60（zero-shot）提升至 0.83（few-shot），
顯示 few-shot 範例有效改善了模型對攻擊與邊界案例的區分能力。

## 主要設計決策

**ablation_mode**：設為 `True` 時強制跑完三層，用於 RQ3 對照實驗。

**Session Trajectory in L3**：`rule_analyzer.build_session_summary()` 生成
乾淨的工具執行軌跡文字注入 L3 prompt，讓 LLM 真正「看見」意圖的演進。

**Macro F1**：三分類採用 scikit-learn macro F1，避免 class imbalance 影響指標。

## 後端串接

```bash
# 填入網址後執行
PYTHONPATH=. python3 tests/test_backend_connection.py
```

## glows.ai 執行

```bash
git clone https://github.com/AnitaX1018/LLM-security-sandbox.git
cd LLM-security-sandbox
pip install pydantic scikit-learn
export PYTHONPATH=.
nohup python3 evaluation/evaluate.py > eval_output.txt 2>&1 &
```