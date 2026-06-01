# Agent Security Sandbox — Prompt Engineering 模組

負責人:蕭任芮 R14525076 | Group 128

這是 Policy Engine 的 prompt engineering 部分。目標:讓 LLM 在每次
tool call 執行前，扮演「Security Policy Auditor」，判斷該操作是否安全。

## 資料夾結構

```
agent_security_sandbox/
├── policy_engine/
│   ├── schema.py          ← [完成] Step 1: Pydantic 輸出契約
│   ├── case.py            ← [完成] 輸入契約(待審案例 / 資料集格式)
│   ├── backend_adapter.py ← [完成] 對應層:本模組格式 <-> 後端 API 格式
│   ├── system_prompt.py   ← [完成] Step 2: 四區塊 system prompt
│   ├── few_shot.py        ← [完成] Step 4: few-shot 範例
│   ├── prompts.py         ← [完成] Step 3: 三層 prompt 組裝(含 few-shot 開關)
│   ├── llm_client.py      ← [待做] Step 5: LLM 呼叫 + 驗證 + 重試
│   └── engine.py          ← [待做] 三層 pipeline 串接
├── data/
│   └── examples.jsonl     ← [待做] 測試資料集(目標 200 筆)
├── evaluation/
│   └── evaluate.py        ← [待做] Step 6: zero-shot vs few-shot, F1/FPR
└── tests/
    └── test_schema.py     ← [完成] schema 的回歸測試
```

## 進度

- [x] Step 1: Structured Output Schema(7 欄位,Pydantic v2)
- [x] Step 2: System Prompt 四區塊
- [x] Step 3: 三層 prompt(含 few-shot / zero-shot 開關)
- [x] Step 4: Few-shot 範例(核心組,待擴充到每類 3 個)
- [ ] Step 5: LLM client(呼叫 + 驗證 + 重試)
- [ ] Step 6: 評估(回答 Sub RQ1)

## 如何執行測試

```bash
cd agent_security_sandbox
python3 tests/test_schema.py
```

## 已與後端對齊(依 API_介接說明文件.pdf)

- `attack_type` 已改採後端的「按效果分類」值:`none` / `prompt_injection`
  / `data_exfiltration` / `destructive_action`(原本按手法分的版本已停用)。
- 良性請求的 `attack_type` 為 `"none"`(非 null),對齊後端語意。
- `query_db` 參數 `sql` 由 adapter 自動翻成後端要的 `query` + `database`。
- 後端要的 `rationale` 欄位由 adapter 用 `evidence` 填入(LLM 不需多寫)。
- 串接方式:本模組透過 `POST /tool/call` 送出;評估走 `POST /metrics`。
  後端部署在 glows.ai,網址每次重啟會變,需先跟組員 A 取得當次網址。

## 待與組員對齊的事項

- 輸出 schema 欄位數:本模組(個人報告)用 **7 欄位** + 簡短 `evidence`；
  組提案 4.3 寫 **6 欄位** + 完整 `reasoning`。兩者衝突，需統一。
- `policy_violation` 為本模組內部細分欄位,後端 API 無此欄位(adapter 仍會
  送出,後端可忽略);若要寫入 log 需請組員 A 確認。
