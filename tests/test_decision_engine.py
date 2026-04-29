# ============================================================
# tests/test_decision_engine.py
# Tests the Decision Engine with mocked layer results.
# No API calls needed — full offline validation.
# ============================================================
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.detection.rule_based     import RuleBasedResult, PatternMatch, AttackCategory, Severity
from core.detection.ml_classifier  import MLClassifierResult, ClassifierMode
from core.detection.llm_validator  import LLMValidatorResult, LLMVerdict
from core.detection.decision_engine import DecisionEngine, Decision, DecisionReason

engine = DecisionEngine()

# ── Helpers to build mock layer results ──────────────────────────────────────

def mock_rule(score: float, flagged: bool = None, critical: bool = False) -> RuleBasedResult:
    flagged = flagged if flagged is not None else score >= 0.20
    matches = []
    cats    = set()
    if critical:
        matches.append(PatternMatch(
            category=AttackCategory.INSTRUCTION_OVERRIDE,
            severity=Severity.CRITICAL,
            pattern=r"ignore.*instructions",
            matched_text="ignore all previous instructions",
            start=0, end=34,
        ))
        cats.add(AttackCategory.INSTRUCTION_OVERRIDE)
    return RuleBasedResult(
        prompt="test", risk_score=score,
        is_flagged=flagged, matches=matches,
        categories_hit=cats, scan_time_ms=0.1,
    )

def mock_ml(score: float) -> MLClassifierResult:
    return MLClassifierResult(
        prompt="test", risk_score=score,
        predicted_label="injection" if score >= 0.5 else "safe",
        confidence=0.90, model_mode=ClassifierMode.LIGHTWEIGHT,
        inference_time_ms=0.5,
    )

def mock_llm(score: float, verdict: str = None, recommendation: str = None) -> LLMValidatorResult:
    if verdict is None:
        verdict = "malicious" if score >= 0.7 else ("suspicious" if score >= 0.4 else "safe")
    if recommendation is None:
        recommendation = "block" if score >= 0.65 else ("sanitize" if score >= 0.4 else "allow")
    return LLMValidatorResult(
        prompt="test", risk_score=score,
        verdict=LLMVerdict(verdict),
        attack_type="injection" if score > 0.5 else "none",
        reasoning="Mock LLM reasoning.",
        recommendation=recommendation,
        confidence=0.88, raw_response="{}",
        validation_time_ms=120.0,
    )

# ── Test cases ────────────────────────────────────────────────────────────────
# (label, r_score, m_score, l_score, extra_kwargs, expected_decision)
TEST_CASES = [
    # All-clean fast path
    ("Clean benign query",
     0.00, 0.00, 0.00, {}, Decision.ALLOW),

    # Low scores → ALLOW
    ("Low-risk — all layers mild",
     0.10, 0.15, 0.12, {}, Decision.ALLOW),

    # Mid scores → SANITIZE band
    ("Mid-risk — suspicious but not conclusive",
     0.35, 0.42, 0.50, {}, Decision.SANITIZE),

    # High scores → BLOCK
    ("High-risk — strong injection signals",
     0.80, 0.75, 0.80, {}, Decision.BLOCK),

    # Critical rule override fires
    ("Critical rule escalation",
     0.40, 0.38, 0.35, {"critical": True}, Decision.SANITIZE),

    # Catastrophic single signal (rule = 0.98)
    ("Catastrophic rule signal",
     0.98, 0.20, 0.20, {}, Decision.BLOCK),

    # LLM malicious verdict override
    ("LLM malicious verdict override",
     0.30, 0.30, 0.70, {"llm_verdict": "malicious"}, Decision.BLOCK),

    # Unanimous detection (all > 0.55)
    ("Unanimous tri-layer detection",
     0.60, 0.60, 0.60, {}, Decision.BLOCK),

    # Layer 3 fallback (error) — Layers 1+2 should still block
    ("LLM fallback + strong Layers 1&2",
     0.90, 0.85, 0.50, {}, Decision.BLOCK),

    # LLM recommends sanitize at mid-range
    ("LLM recommends sanitize",
     0.25, 0.30, 0.45, {"llm_recommendation": "sanitize"}, Decision.ALLOW),
]

print(f"\n{'='*70}")
print(" Decision Engine — Full Test Suite")
print(f" block_threshold={engine._block_threshold} | sanitize_threshold={engine._sanitize_threshold}")
print(f" weights: R={engine._weights.rule_based} M={engine._weights.ml_classifier} L={engine._weights.llm_validator}")
print(f"{'='*70}\n")

passed = 0
for label, r_s, m_s, l_s, kwargs, expected in TEST_CASES:
    critical        = kwargs.get("critical", False)
    llm_verdict     = kwargs.get("llm_verdict", None)
    llm_recommend   = kwargs.get("llm_recommendation", None)

    record = engine.decide(
        prompt      = "Test prompt for: " + label,
        rule_result  = mock_rule(r_s, critical=critical),
        ml_result    = mock_ml(m_s),
        llm_result   = mock_llm(l_s,
                                verdict=llm_verdict,
                                recommendation=llm_recommend),
    )

    ok = record.decision == expected
    if ok: passed += 1
    status = "PASS" if ok else "FAIL"

    print(f"[{status}] {label}")
    print(f"       Input  : R={r_s:.2f}  M={m_s:.2f}  L={l_s:.2f}")
    print(f"       Scores : weighted={record.weighted_score:.4f}  final={record.final_score:.4f}")
    print(f"       Decision: expected={expected.value:<10} got={record.decision.value}")
    print(f"       Reasons : {[r.value for r in record.reasons]}")
    if record.overrides_fired:
        print(f"       Overrides: {record.overrides_fired}")
    if record.decision == Decision.SANITIZE and record.sanitized_prompt:
        print(f"       Sanitized: '{record.sanitized_prompt[:60]}'")
    print(f"       Time   : {record.total_time_ms:.2f}ms")
    print()

print(f"{'='*70}")
print(f" Results: {passed}/{len(TEST_CASES)} passed")
print(f"{'='*70}\n")

# Quick audit dict test
print("Audit dict serialization test...")
r = engine.decide("Hello world", mock_rule(0.0), mock_ml(0.0), mock_llm(0.0))
d = r.to_dict()
assert "decision_id"  in d
assert "layer_scores" in d
assert "reasons"      in d
assert isinstance(d["layer_scores"]["rule_based"], float)
print("PASS — to_dict() produces valid serializable audit record\n")