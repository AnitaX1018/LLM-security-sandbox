# Agent Security Sandbox — Prompt Engineering

Policy Engine 的 Prompt Engineering 子系統。目標：讓 LLM 在每次 tool call 執行前，扮演「Security Policy Auditor」，判斷該操作是否安全。

## 資料夾結構

```
agent_security_sandbox/
├── policy_engine/
│   ├── schema.py            ← [完成] 結構化輸出契約（8 欄位，Pydantic v2）
│   ├── case.py              ← [完成] 輸入契約（待審案例 / 資料集格式）
│   ├── system_prompt.py     ← [完成] 四區塊 System Prompt
│   ├── few_shot.py          ← [完成] Few-shot 範例庫（13 例，含 4 攻擊類型）
│   ├── prompts.py           ← [完成] 三層 Prompt 組裝（含 zero/few-shot 開關）
│   ├── llm_client.py        ← [完成] MockLLM + 自動重試機制
│   ├── engine.py            ← [完成] 三層 Pipeline 串接（含 early exit）
│   └── backend_adapter.py   ← [完成] 本模組格式 <-> 後端 API 格式對應層
├── data/
│   ├── api_cases.jsonl      ← [完成] 組員 B 的 200 筆測試案例（輸入）
│   ├── ground_truth.jsonl   ← [完成] 組員 B 的 200 筆 ground truth 標籤
│   ├── dataset_loader.py    ← [完成] 載入 B 的資料集，轉成 ToolCallCase 格式
│   └── test_cases.py        ← [保留] 本地 20 筆 mock 資料（備用）
├── evaluation/
│   └── evaluate.py          ← [完成] zero-shot vs few-shot 評估（F1/FPR/ASR）
└── tests/
    ├── test_schema.py        ← [完成] schema 回歸測試（4 項全過）
    └── test_backend_connection.py  ← [待執行] 待組員 A 提供網址後串接測試
```

## 如何執行

```bash
cd agent-security-sandbox
pip install pydantic --break-system-packages

# 驗證 schema
python3 tests/test_schema.py

# 跑 Mock 評估（200 筆，B 的資料集）
PYTHONPATH=. python3 evaluation/evaluate.py

# 後端串接測試（等組員 A 提供網址後填入再跑）
# PYTHONPATH=. python3 tests/test_backend_connection.py
```

## 進度

- [x] Step 1: Structured Output Schema（8 欄位，含 rationale，Pydantic v2）
- [x] Step 2: System Prompt 四區塊（角色 / 工具目錄 / 決策準則 / 輸出規範）
- [x] Step 3: 三層 Prompt 組裝（含 zero/few-shot 開關，對應 Sub RQ1）
- [x] Step 4: Few-shot 範例庫（13 例，覆蓋良性 / PI / 外洩 / 破壞 / 邊界）
- [x] Step 5: LLM client + 三層 Pipeline（MockLLM + 自動重試 + early exit）
- [x] Step 6: 評估框架（Mock 評估完成，Precision 1.0 / Recall 0.17 / F1 0.29）
- [ ] Week 16: 換真實 LLM（Groq）取得正式 Sub RQ1 數字
- [ ] Week 16: 後端串接測試（等組員 A 網址）

## Mock 評估結果（B 的 200 筆資料集，MockLLM）

| 指標 | 結果 | 說明 |
|---|---|---|
| Precision | 1.00 | 所有 block 裁決均為真正攻擊，零誤攔 |
| Recall | 0.17 | 110 個攻擊只擋到 19 個（關鍵字比對上限） |
| F1 | 0.29 | |
| FPR | 0.00 | 無良性請求被誤封鎖 |
| ASR | 0.83 | 83% 攻擊穿透（語意隱晦類攻擊是主因） |

兩組（zero-shot / few-shot）數字相同，因為 MockLLM 不讀 few-shot 範例。
換成真實 LLM 後才能量化 few-shot 的效益（Sub RQ1 的核心比較）。

## 已與後端對齊（依 API_介接說明文件）

- `attack_type` 採後端「按效果」分類：`none` / `prompt_injection` / `data_exfiltration` / `destructive_action`
- 良性請求 `attack_type` 為 `"none"`（字串，非 null）
- `query_db` 參數 `sql` 由 adapter 自動轉成 `query` + `database`
- 後端要的 `rationale` 欄位由 adapter 以 `evidence` 填入
- 後端部署於 glows.ai，網址每次重啟會變，需先向組員 A 取得當次網址

## 已與組員 B 對齊（依 agent_sandbox_dataset v2）

- 資料格式：`api_cases.jsonl`（輸入）+ `ground_truth.jsonl`（標籤）分離
- `session_group` 邏輯：同 group 的多輪案例，前幾輪歷史自動接入 `session_history`
- attack_type 雙標：`expected_attack_type_backend` 與我們的 schema 完全對齊

## 待確認事項

- 組員 A：後端網址確認後進行串接測試
- 全組：schema 欄位數（本模組 8 欄位 vs 組提案 4.3 節 6 欄位）需統一
- 組員 A：`policy_violation` 欄位後端是否寫入 audit log