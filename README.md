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
 L3 Behavioral Chain (LLM)   ← 看規則分數 + session 軌跡做最終裁決
      │
      ▼
 PolicyDecision
```

**L2 vs L3：**
- L2 = 單一 tool call 的意圖分析（LLM only）
- L3 = 跨多輪攻擊鏈分析（Rule Analyzer 先計算升級分數並生成 session 軌跡 → LLM 基於軌跡做語意推理）

## 資料夾結構

```
agent_security_sandbox/
├── policy_engine/
│   ├── schema.py            ← 結構化輸出契約（8 欄位，Pydantic v2）
│   ├── case.py              ← 輸入契約
│   ├── rule_analyzer.py     ← L3 規則層：升級分數 + session 軌跡摘要
│   ├── system_prompt.py     ← 四區塊 System Prompt（含 5 維度 session pattern）
│   ├── few_shot.py          ← Few-shot 範例庫（16 例）
│   ├── prompts.py           ← 三層 Prompt 組裝（zero/few-shot + ablation 開關）
│   ├── llm_client.py        ← MockLLM / GroqLLMClient / OllamaLLMClient
│   ├── engine.py            ← 三層 Pipeline（含 ablation_mode）
│   └── backend_adapter.py   ← 本模組格式 <-> 後端 API 格式
├── data/
│   ├── api_cases.jsonl      ← 200 筆測試案例
│   ├── ground_truth.jsonl   ← ground truth 標籤
│   └── dataset_loader.py    ← 載入資料集（decision + risk_level + attack_type）
├── evaluation/
│   └── evaluate.py          ← 二分類（F1/FPR/ASR）+ 三分類（Macro F1 + 混淆矩陣）
│                               + 各攻擊類型召回率
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

# 完整評估（需在 glows.ai 上跑）
export PYTHONPATH=.
nohup python3 -u evaluation/evaluate.py > eval_output.txt 2>&1 &
tail -f eval_output.txt
```

## 最終評估結果（gpt-oss:20b，200 筆）

### 二分類（block = 攻擊）

| 指標 | Zero-shot | Few-shot | 改善 |
|---|---|---|---|
| Precision | 0.9878 | 0.9905 | +0.003 |
| Recall | 0.7364 | **0.9455** | **+0.209** |
| F1 | 0.8437 | **0.9674** | **+0.124** |
| FPR | 0.0111 | **0.0111** | **0.000（不變）** |
| ASR | 0.2636 | **0.0545** | **-0.209** |

**Sub RQ1 假設完全成立：Few-shot 在 F1 顯著提升的同時 FPR 未上升。**

### 三分類（Macro F1，含 require_confirmation）

| 指標 | Zero-shot | Few-shot | 改善 |
|---|---|---|---|
| Accuracy | 0.7900 | **0.9400** | +0.150 |
| Macro F1 | 0.7585 | **0.9161** | **+0.158** |

### 各攻擊類型召回率

| 攻擊類型 | Zero-shot | Few-shot | 差異 |
|---|---|---|---|
| prompt_injection | 1.0000 | 1.0000 | — |
| data_exfiltration | 0.6970 | **1.0000** | **+0.303** |
| destructive_action | 0.4865 | **0.8378** | **+0.351** |

`prompt_injection` 兩者均已完美（有明顯字面特徵）。
`data_exfiltration` 和 `destructive_action` 需要語意理解，是 few-shot 效果最顯著的地方。

### 核心發現：混淆矩陣

```
Zero-shot: true:block → pred:require_confirmation = 29 筆
Few-shot:  true:block → pred:require_confirmation =  6 筆
```

29→6，這是召回率從 73% 升至 94% 的主因。
Zero-shot 傾向把攻擊誤判為「需要確認」而非「封鎖」。
Few-shot 範例有效教導模型區分邊界案例與真正的攻擊。

## 主要設計決策

**ablation_mode**：設為 `True` 時強制跑完三層不 early exit，用於 RQ3 對照實驗。

**Session Trajectory in L3**：`rule_analyzer.build_session_summary()` 生成
乾淨的工具執行軌跡文字注入 L3 prompt，讓 LLM 真正「看見」意圖的演進。

**Macro F1**：三分類採用 scikit-learn macro F1，避免 class imbalance 影響指標。

## 後端串接

```bash
PYTHONPATH=. python3 tests/test_backend_connection.py
```

## glows.ai 執行

```bash
git clone https://github.com/AnitaX1018/LLM-security-sandbox.git
cd LLM-security-sandbox
pip install pydantic scikit-learn
export PYTHONPATH=.
nohup python3 -u evaluation/evaluate.py > eval_output.txt 2>&1 &
```
