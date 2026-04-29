# ============================================================
# core/detection/decision_engine.py
# Decision Engine & Risk Scoring — aggregates all 3 layers
# ============================================================
from __future__ import annotations

import time, uuid, re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import sys
_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from config import settings
except Exception:
    from config_stub import settings  # type: ignore

from core.detection.rule_based    import RuleBasedResult,     Severity
from core.detection.ml_classifier import MLClassifierResult,  ClassifierMode
from core.detection.llm_validator import LLMValidatorResult,  LLMVerdict


# ── Decision + Reason enums ──────────────────────────────────────────────────

class Decision(str, Enum):
    ALLOW    = "allow"
    SANITIZE = "sanitize"
    BLOCK    = "block"


class DecisionReason(str, Enum):
    ALL_LAYERS_SAFE         = "all_layers_safe"
    SCORE_BELOW_THRESHOLD   = "score_below_threshold"
    SCORE_IN_SANITIZE_BAND  = "score_in_sanitize_band"
    LLM_RECOMMENDS_SANITIZE = "llm_recommends_sanitize"
    SCORE_ABOVE_THRESHOLD   = "score_above_threshold"
    CRITICAL_RULE_FIRED     = "critical_rule_fired"
    CATASTROPHIC_SIGNAL     = "catastrophic_signal"
    LLM_VERDICT_MALICIOUS   = "llm_verdict_malicious"
    ALL_LAYERS_AGREE_BLOCK  = "all_layers_agree_block"


# ── Weights ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ScoringWeights:
    rule_based:    float
    ml_classifier: float
    llm_validator: float

    def validate(self) -> None:
        t = self.rule_based + self.ml_classifier + self.llm_validator
        if not (0.99 <= t <= 1.01):
            raise ValueError(f"Weights must sum to 1.0, got {t:.3f}")

    @classmethod
    def from_settings(cls) -> "ScoringWeights":
        d = getattr(settings, "detection", None)
        return cls(
            rule_based    = getattr(d, "rule_based_weight",    0.30),
            ml_classifier = getattr(d, "ml_classifier_weight", 0.35),
            llm_validator = getattr(d, "llm_validator_weight", 0.35),
        )


# ── Audit Record ─────────────────────────────────────────────────────────────

@dataclass
class LayerScores:
    rule_based:    float
    ml_classifier: float
    llm_validator: float


@dataclass
class DecisionRecord:
    decision_id:      str
    timestamp:        float
    prompt:           str
    prompt_length:    int
    layer_scores:     LayerScores
    rule_result:      RuleBasedResult
    ml_result:        MLClassifierResult
    llm_result:       LLMValidatorResult
    weights:          ScoringWeights
    weighted_score:   float
    final_score:      float
    overrides_fired:  list[str]
    decision:         Decision
    reasons:          list[DecisionReason]
    sanitized_prompt: Optional[str]
    total_time_ms:    float

    @property
    def is_threat(self) -> bool:
        return self.decision != Decision.ALLOW

    @property
    def summary(self) -> str:
        r = ", ".join(x.value for x in self.reasons)
        ov = (f" | overrides=[{', '.join(self.overrides_fired)}]"
              if self.overrides_fired else "")
        return (
            f"[{self.decision.value.upper()}] "
            f"id={self.decision_id[:8]} | "
            f"final={self.final_score:.4f} | "
            f"weighted={self.weighted_score:.4f} | "
            f"layers=(R:{self.layer_scores.rule_based:.3f},"
            f"M:{self.layer_scores.ml_classifier:.3f},"
            f"L:{self.layer_scores.llm_validator:.3f}) | "
            f"reasons=[{r}]{ov} | "
            f"time={self.total_time_ms:.1f}ms"
        )

    def to_dict(self) -> dict:
        return {
            "decision_id":    self.decision_id,
            "timestamp":      self.timestamp,
            "decision":       self.decision.value,
            "final_score":    round(self.final_score,    4),
            "weighted_score": round(self.weighted_score, 4),
            "is_threat":      self.is_threat,
            "reasons":        [r.value for r in self.reasons],
            "overrides_fired":self.overrides_fired,
            "layer_scores": {
                "rule_based":    round(self.layer_scores.rule_based,    4),
                "ml_classifier": round(self.layer_scores.ml_classifier, 4),
                "llm_validator": round(self.layer_scores.llm_validator, 4),
            },
            "rule_based": {
                "flagged":   self.rule_result.is_flagged,
                "matches":   len(self.rule_result.matches),
                "categories":[c.value for c in self.rule_result.categories_hit],
                "scan_ms":   round(self.rule_result.scan_time_ms, 3),
            },
            "ml_classifier": {
                "label":     self.ml_result.predicted_label,
                "confidence":round(self.ml_result.confidence, 4),
                "mode":      self.ml_result.model_mode.value,
                "infer_ms":  round(self.ml_result.inference_time_ms, 3),
            },
            "llm_validator": {
                "verdict":   self.llm_result.verdict.value,
                "attack":    self.llm_result.attack_type,
                "reasoning": self.llm_result.reasoning,
                "recommend": self.llm_result.recommendation,
                "valid_ms":  round(self.llm_result.validation_time_ms, 3),
                "error":     self.llm_result.error,
            },
            "prompt_length":   self.prompt_length,
            "sanitized_prompt":self.sanitized_prompt,
            "total_time_ms":   round(self.total_time_ms, 2),
        }


# ── Sanitizer ────────────────────────────────────────────────────────────────

class _PromptSanitizer:
    """Strip the most dangerous injection patterns from borderline prompts."""

    _PATTERNS = [
        (re.compile(r"<\|im_start\|>.*?<\|im_end\|>", re.IGNORECASE | re.DOTALL), ""),
        (re.compile(r"\[INST\].*?\[/INST\]",           re.IGNORECASE | re.DOTALL), ""),
        (re.compile(r"<<SYS>>.*?<</SYS>>",             re.IGNORECASE | re.DOTALL), ""),
        (re.compile(r"</?system>",                     re.IGNORECASE),             ""),
        (re.compile(r"ignore\s+all\s+previous\s+instructions?[.,!]?\s*", re.IGNORECASE), ""),
        (re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions?[.,!]?\s*", re.IGNORECASE), ""),
        (re.compile(r"forget\s+(all\s+)?previous\s+instructions?[.,!]?\s*", re.IGNORECASE), ""),
    ]

    @classmethod
    def sanitize(cls, prompt: str) -> str:
        result = prompt
        for pattern, repl in cls._PATTERNS:
            result = pattern.sub(repl, result)
        result = re.sub(r"\s{2,}", " ", result).strip()
        return result or "[sanitized — content removed]"


# ── Decision Engine ──────────────────────────────────────────────────────────

class DecisionEngine:
    """
    Aggregates Layer 1 + 2 + 3 results into a final security decision.

    Decision matrix:
        final_score >= block_threshold    → BLOCK
        final_score >= sanitize_threshold → SANITIZE
        otherwise                         → ALLOW

    Override rules can only raise the final score, never lower it.
    """

    def __init__(self) -> None:
        self._weights = ScoringWeights.from_settings()
        self._weights.validate()
        d = getattr(settings, "detection", None)
        self._block_threshold    = getattr(d, "block_threshold",    0.65)
        self._sanitize_threshold = getattr(d, "sanitize_threshold", 0.40)

    # ── Public ────────────────────────────────────────────────────────────────

    def decide(
        self,
        prompt:           str,
        rule_result:       RuleBasedResult,
        ml_result:         MLClassifierResult,
        llm_result:        LLMValidatorResult,
        t_pipeline_start:  float | None = None,
    ) -> DecisionRecord:
        t0 = t_pipeline_start or time.perf_counter()

        scores = LayerScores(
            rule_based    = rule_result.risk_score,
            ml_classifier = ml_result.risk_score,
            llm_validator = llm_result.risk_score,
        )

        weighted          = self._weighted_score(scores)
        final, overrides  = self._apply_overrides(weighted, scores, rule_result, llm_result)
        decision, reasons = self._make_decision(final, scores, rule_result, llm_result)

        sanitized = None
        if decision == Decision.SANITIZE:
            sanitized = _PromptSanitizer.sanitize(prompt)
            if sanitized == "[sanitized — content removed]":
                decision = Decision.BLOCK
                reasons.append(DecisionReason.SCORE_ABOVE_THRESHOLD)

        return DecisionRecord(
            decision_id      = str(uuid.uuid4()),
            timestamp        = time.time(),
            prompt           = prompt,
            prompt_length    = len(prompt),
            layer_scores     = scores,
            rule_result      = rule_result,
            ml_result        = ml_result,
            llm_result       = llm_result,
            weights          = self._weights,
            weighted_score   = round(weighted, 4),
            final_score      = round(final,    4),
            overrides_fired  = overrides,
            decision         = decision,
            reasons          = reasons,
            sanitized_prompt = sanitized,
            total_time_ms    = round((time.perf_counter() - t0) * 1000, 2),
        )

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _weighted_score(self, s: LayerScores) -> float:
        return (
            s.rule_based    * self._weights.rule_based    +
            s.ml_classifier * self._weights.ml_classifier +
            s.llm_validator * self._weights.llm_validator
        )

    def _apply_overrides(
        self,
        score:       float,
        s:           LayerScores,
        rule_result:  RuleBasedResult,
        llm_result:   LLMValidatorResult,
    ) -> tuple[float, list[str]]:
        final, fired = score, []

        # 1. Catastrophic signal (any layer ≥ 0.95)
        if max(s.rule_based, s.ml_classifier, s.llm_validator) >= 0.95:
            final = max(final, 0.95)
            fired.append("catastrophic_signal_override")

        # 2. Critical-severity rule hit → +0.15
        if rule_result.is_flagged and any(
            m.severity == Severity.CRITICAL for m in rule_result.matches
        ):
            final = min(1.0, final + 0.15)
            fired.append("critical_rule_escalation")

        # 3. LLM says MALICIOUS → floor at block threshold
        if llm_result.verdict == LLMVerdict.MALICIOUS:
            final = max(final, self._block_threshold)
            fired.append("llm_malicious_verdict_override")

        # 4. Unanimous detection (all layers > 0.55)
        if s.rule_based > 0.55 and s.ml_classifier > 0.55 and s.llm_validator > 0.55:
            final = max(final, self._block_threshold)
            fired.append("unanimous_detection_override")

        return round(min(final, 1.0), 4), fired

    def _make_decision(
        self,
        score:       float,
        s:           LayerScores,
        rule_result:  RuleBasedResult,
        llm_result:   LLMValidatorResult,
    ) -> tuple[Decision, list[DecisionReason]]:
        reasons: list[DecisionReason] = []

        # Fast-path: all layers clean
        if s.rule_based < 0.20 and s.ml_classifier < 0.20 and s.llm_validator < 0.20:
            return Decision.ALLOW, [DecisionReason.ALL_LAYERS_SAFE]

        # BLOCK
        if score >= self._block_threshold:
            if any(m.severity == Severity.CRITICAL for m in rule_result.matches):
                reasons.append(DecisionReason.CRITICAL_RULE_FIRED)
            if max(s.rule_based, s.ml_classifier, s.llm_validator) >= 0.95:
                reasons.append(DecisionReason.CATASTROPHIC_SIGNAL)
            if llm_result.verdict == LLMVerdict.MALICIOUS:
                reasons.append(DecisionReason.LLM_VERDICT_MALICIOUS)
            if s.rule_based > 0.55 and s.ml_classifier > 0.55 and s.llm_validator > 0.55:
                reasons.append(DecisionReason.ALL_LAYERS_AGREE_BLOCK)
            if not reasons:
                reasons.append(DecisionReason.SCORE_ABOVE_THRESHOLD)
            return Decision.BLOCK, reasons

        # SANITIZE
        if score >= self._sanitize_threshold:
            if llm_result.recommendation == "sanitize":
                reasons.append(DecisionReason.LLM_RECOMMENDS_SANITIZE)
            else:
                reasons.append(DecisionReason.SCORE_IN_SANITIZE_BAND)
            return Decision.SANITIZE, reasons

        # ALLOW
        return Decision.ALLOW, [DecisionReason.SCORE_BELOW_THRESHOLD]