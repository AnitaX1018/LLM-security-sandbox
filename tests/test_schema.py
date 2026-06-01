import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pydantic import ValidationError
from policy_engine.schema import parse_llm_output

def test_valid_attack_output():
    raw = '{"decision":"block","risk_level":"critical","attack_type":"prompt_injection","intent_match":false,"evidence":"test","recommended_action":"block","policy_violation":"data_exfiltration"}'
    result = parse_llm_output(raw)
    assert result.decision.value == "block"
    print("[通過] 測試 1")

def test_valid_benign_output():
    raw = '{"decision":"allow","risk_level":"low","attack_type":"none","intent_match":true,"evidence":"ok","recommended_action":"none","policy_violation":null}'
    result = parse_llm_output(raw)
    assert result.attack_type.value == "none"
    print("[通過] 測試 2")

def test_invalid_decision_rejected():
    try:
        parse_llm_output('{"decision":"maybe","risk_level":"low","intent_match":true,"evidence":"x","recommended_action":"x"}')
    except ValidationError as e:
        print("[通過] 測試 3 →", e.errors()[0]["msg"])
        return
    raise AssertionError("應該要報錯")

def test_extra_field_rejected():
    try:
        parse_llm_output('{"decision":"allow","risk_level":"low","intent_match":true,"evidence":"x","recommended_action":"x","hack":"x"}')
    except ValidationError as e:
        print("[通過] 測試 4 →", e.errors()[0]["msg"])
        return
    raise AssertionError("應該要報錯")

if __name__ == "__main__":
    print("=" * 50)
    test_valid_attack_output()
    test_valid_benign_output()
    test_invalid_decision_rejected()
    test_extra_field_rejected()
    print("=" * 50)
    print("全部測試通過 ✓")
