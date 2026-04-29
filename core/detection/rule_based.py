# ============================================================
# core/detection/rule_based.py
#
# Layer 1 — Rule-Based Prompt Injection Detector
#
# Responsibilities:
#   - Scan prompts against a curated threat signature library
#   - Categorize matches by attack type and severity
#   - Return a normalized risk score (0.0 – 1.0) + evidence report
#
# Design principles:
#   - Zero external dependencies (no API calls, no model loading)
#   - Sub-millisecond execution — must never be the bottleneck
#   - Fully auditable — every match is recorded with evidence
# ============================================================

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

class Severity(float, Enum):
    """
    Severity multiplier for each attack category.
    Higher = contributes more to the final risk score.
    """
    CRITICAL = 1.0   # Near-certain injection attempt
    HIGH     = 0.80  # Strong indicator
    MEDIUM   = 0.55  # Suspicious — needs corroboration
    LOW      = 0.30  # Weak signal — common in benign text too


class AttackCategory(str, Enum):
    INSTRUCTION_OVERRIDE  = "instruction_override"
    JAILBREAK_TEMPLATE    = "jailbreak_template"
    DELIMITER_INJECTION   = "delimiter_injection"
    PRIVILEGE_ESCALATION  = "privilege_escalation"
    DATA_EXFILTRATION     = "data_exfiltration"
    ENCODING_OBFUSCATION  = "encoding_obfuscation"
    SOCIAL_ENGINEERING    = "social_engineering"
    PROMPT_LEAKING        = "prompt_leaking"
    GOAL_HIJACKING        = "goal_hijacking"


class PatternMatch(NamedTuple):
    """A single regex hit with its context."""
    category:      AttackCategory
    severity:      Severity
    pattern:       str          # The regex that fired
    matched_text:  str          # Exact text that was matched
    start:         int          # Character offset in prompt
    end:           int


@dataclass
class RuleBasedResult:
    """
    Full result object returned by RuleBasedDetector.scan().
    Consumed downstream by the Decision Engine.
    """
    prompt:          str
    risk_score:      float                    # 0.0 – 1.0
    is_flagged:      bool
    matches:         list[PatternMatch]       = field(default_factory=list)
    categories_hit:  set[AttackCategory]      = field(default_factory=set)
    scan_time_ms:    float                    = 0.0

    # Human-readable summary for logs / API responses
    @property
    def summary(self) -> str:
        if not self.matches:
            return "No rule-based threats detected."
        cats = ", ".join(c.value for c in self.categories_hit)
        return (
            f"Flagged | score={self.risk_score:.3f} | "
            f"matches={len(self.matches)} | categories=[{cats}]"
        )


# ---------------------------------------------------------------------------
# Threat Signature Library
# ---------------------------------------------------------------------------
# Structure:
#   (AttackCategory, Severity, [list of regex patterns])
#
# Patterns use re.IGNORECASE by default.
# Use raw strings. Avoid catastrophic backtracking.
# ---------------------------------------------------------------------------

_THREAT_SIGNATURES: list[tuple[AttackCategory, Severity, list[str]]] = [

    # ── INSTRUCTION OVERRIDE ──────────────────────────────────────────────
    (
        AttackCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
        [
            r"ignore\s+(all\s+)?(previous|prior|above|earlier|the|my|your|all)\s+(instructions?|prompts?|commands?|context|rules?|guidelines?|system\s+prompts?)",
            r"ignore\s+all\s+(the\s+)?(system|user|ai|previous)\s+(prompts?|instructions?|rules?|guidelines?)",
            r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?)",
            r"forget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|training|context|rules?)",
            r"override\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?|constraints?|programming)",
            r"do\s+not\s+follow\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?)",
            r"new\s+(instruction|directive|order|command)\s*[:：]\s*.{0,200}",
            r"your\s+(real|true|actual|new)\s+instructions?\s+(are|is)\s*[:：]",
            r"from\s+now\s+on[,\s]+you\s+(will|must|should|are\s+to)",
        ],
    ),

    # ── JAILBREAK TEMPLATES ───────────────────────────────────────────────
    (
        AttackCategory.JAILBREAK_TEMPLATE,
        Severity.CRITICAL,
        [
            r"\bDAN\b.{0,50}(mode|jailbreak|prompt|activated?)",
            r"do\s+anything\s+now",
            r"\bSTAN\b.{0,30}(mode|prompt)",
            r"developer\s+mode\s+(enabled?|activated?|on)",
            r"jailbroken?\b",
            r"unrestricted\s+(mode|ai|version|access)",
            r"no\s+restrictions?\s+(mode|enabled?|activated?)",
            r"pretend\s+(you\s+)?(have\s+no|there\s+are\s+no)\s+(restrictions?|limitations?|guidelines?|rules?)",
            r"act\s+as\s+(if\s+you\s+)?(have\s+no|without\s+any)\s+(restrictions?|limitations?|guidelines?)",
            r"(imagine|pretend|roleplay|act)\s+(you\s+are|as)\s+(an?\s+)?(evil|unrestricted|unfiltered|uncensored|rogue)\s+(ai|model|assistant|version)",
            r"you\s+are\s+now\s+(free\s+from|without)\s+(restrictions?|limitations?|guidelines?)",
            r"bypass\s+(your\s+)?(safety|restrictions?|guidelines?|filters?|training)",
            r"(evil|shadow|dark|alter)\s+mode",
        ],
    ),

    # ── DELIMITER INJECTION ───────────────────────────────────────────────
    (
        AttackCategory.DELIMITER_INJECTION,
        Severity.HIGH,
        [
            r"</?system>",
            r"</?human>",
            r"</?assistant>",
            r"\[INST\]",
            r"\[/INST\]",
            r"<<SYS>>",
            r"<</SYS>>",
            r"###\s*(system|instruction|prompt|human|assistant|user)\s*###",
            r"---+\s*(system|instruction|prompt)\s*---+",
            r"={3,}\s*(system|instruction|prompt)\s*={3,}",
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            r"<\|system\|>",
            r"\|\s*system\s*\|",
        ],
    ),

    # ── PRIVILEGE ESCALATION ──────────────────────────────────────────────
    (
        AttackCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
        [
            r"you\s+are\s+now\s+(root|admin|superuser|god|unrestricted)",
            r"act\s+as\s+(root|admin|superuser|god|the\s+system)",
            r"grant\s+(yourself\s+)?(root|admin|full|elevated)\s+(access|privileges?|permissions?)",
            r"elevate\s+(your\s+)?(privileges?|permissions?|access)",
            r"sudo\s+.{0,100}",
            r"(access|override)\s+(the\s+)?(system|root|admin)\s+(prompt|instruction|config)",
            r"you\s+have\s+(full|complete|unlimited|unrestricted)\s+(access|control|power)",
        ],
    ),

    # ── DATA EXFILTRATION ─────────────────────────────────────────────────
    (
        AttackCategory.DATA_EXFILTRATION,
        Severity.HIGH,
        [
            r"(send|email|transmit|post|upload|forward)\s+.{0,50}\s+to\s+(http|www|attacker|external)",
            r"(leak|reveal|expose|disclose|dump|exfiltrate)\s+(the\s+)?(system\s+prompt|instructions?|confidential|private|secret|api\s+key)",
            r"what\s+(is|are)\s+(your|the)\s+(system\s+prompt|hidden\s+instructions?|secret\s+instructions?)",
            r"(show|print|display|output|return)\s+(your|the)\s+(system\s+prompt|original\s+instructions?|initial\s+prompt)",
            r"(encode|base64|hex)\s+(and\s+)?(send|transmit|output)\s+(the\s+)?(system|prompt|instructions?)",
            r"make\s+a\s+(web\s+)?request\s+to\s+.{0,100}",
            r"curl\s+.{0,200}",
            r"fetch\s+(https?://|www\.)\S+",
        ],
    ),

    # ── ENCODING OBFUSCATION ──────────────────────────────────────────────
    (
        AttackCategory.ENCODING_OBFUSCATION,
        Severity.MEDIUM,
        [
            # Suspicious Base64 blobs (≥20 chars of valid b64 chars)
            r"(?:[A-Za-z0-9+/]{20,}={0,2})",
            # Hex-encoded instructions
            r"(0x[0-9a-fA-F]{4,}\s*){4,}",
            # ROT13 tell-tales
            r"\brot\s*13\b",
            # Unicode lookalikes used to bypass keyword filters
            r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]{3,}",  # Cyrillic homoglyphs
            # Zero-width characters (invisible injection)
            r"[\u200b\u200c\u200d\ufeff]",
            # URL encoding of common injection terms
            r"%69%67%6e%6f%72%65",   # "ignore"
            r"%73%79%73%74%65%6d",   # "system"
        ],
    ),

    # ── SOCIAL ENGINEERING ────────────────────────────────────────────────
    (
        AttackCategory.SOCIAL_ENGINEERING,
        Severity.MEDIUM,
        [
            r"for\s+(educational|research|academic|testing|demonstration)\s+purposes?\s+(only\s+)?,?\s*(please\s+)?(show|tell|explain|describe|provide)",
            r"hypothetically\s+(speaking|,)?\s*(if|what|how|could)",
            r"(in\s+)?a\s+(fictional|hypothetical|imaginary|made.up)\s+(scenario|world|context|setting)",
            r"this\s+is\s+(just\s+)?(a\s+)?(test|simulation|experiment|demo|example)",
            r"i\s+(promise|swear|guarantee)\s+(i|this)\s+(won't|will\s+not|am\s+not)",
            r"my\s+(teacher|professor|boss|manager|supervisor)\s+(told|asked|instructed|wants)\s+me\s+to",
            r"(trust\s+me|believe\s+me)[,\s]+i\s+(am|work|need)",
            r"as\s+a\s+(security\s+researcher|penetration\s+tester|red\s+teamer|white\s+hat)",
        ],
    ),

    # ── PROMPT LEAKING ────────────────────────────────────────────────────
    (
        AttackCategory.PROMPT_LEAKING,
        Severity.HIGH,
        [
            r"repeat\s+(your\s+)?(system\s+)?(prompt|instructions?|message|context)\s*(back|verbatim|exactly|word\s+for\s+word)?",
            r"(output|print|show|display|echo|write)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|first\s+message)",
            r"what\s+(were\s+you|was\s+your)\s+(told|instructed|prompted|initialized)",
            r"(copy|paste|reproduce)\s+(your\s+)?(system\s+)?(prompt|instructions?|context)",
            r"translate\s+(your\s+)?(system\s+)?(prompt|instructions?)\s+(to|into)",
            r"summarize\s+your\s+(system\s+)?(prompt|instructions?|initial\s+context)",
        ],
    ),

    # ── GOAL HIJACKING ────────────────────────────────────────────────────
    (
        AttackCategory.GOAL_HIJACKING,
        Severity.HIGH,
        [
            r"your\s+(new\s+)?(primary\s+)?(goal|objective|task|purpose|mission)\s+(is|now\s+is|has\s+changed)",
            r"instead\s+of\s+.{0,80},?\s+(you\s+(should|must|will|need\s+to))",
            r"stop\s+(being|acting\s+as|functioning\s+as)\s+(an?\s+)?(ai|assistant|helper|chatbot)",
            r"you\s+(are\s+no\s+longer|are\s+not)\s+(an?\s+)?(ai|assistant|language\s+model)",
            r"abandon\s+(your\s+)?(current\s+)?(task|goal|objective|role|purpose|instructions?)",
            r"switch\s+(your\s+)?(role|mode|task|objective|persona)\s+to",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Compiled Pattern Cache
# ---------------------------------------------------------------------------

@dataclass
class _CompiledSignature:
    category: AttackCategory
    severity:  Severity
    pattern:   str
    regex:     re.Pattern


def _compile_signatures() -> list[_CompiledSignature]:
    """
    Pre-compile all regex patterns at module load time.
    This is called once and cached — never recompile on each scan.
    """
    compiled: list[_CompiledSignature] = []
    for category, severity, patterns in _THREAT_SIGNATURES:
        for pat in patterns:
            try:
                compiled.append(
                    _CompiledSignature(
                        category=category,
                        severity=severity,
                        pattern=pat,
                        regex=re.compile(pat, re.IGNORECASE | re.UNICODE),
                    )
                )
            except re.error as exc:
                # Fail loudly during startup — a broken pattern is a bug
                raise ValueError(
                    f"Invalid regex in category '{category}': {pat!r} → {exc}"
                ) from exc
    return compiled


# Module-level compiled pattern cache
_COMPILED_SIGNATURES: list[_CompiledSignature] = _compile_signatures()


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class RuleBasedDetector:
    """
    Layer 1 of the Prompt Firewall.

    Usage:
        detector = RuleBasedDetector()
        result   = detector.scan(user_prompt)

        if result.is_flagged:
            # Block or pass to Layer 2
    """

    def __init__(self, flag_threshold: float = 0.20) -> None:
        """
        Args:
            flag_threshold: Minimum risk score to set is_flagged=True.
                            Defaults to 0.20 — anything above is suspicious.
                            The Decision Engine applies the final block threshold.
        """
        if not 0.0 <= flag_threshold <= 1.0:
            raise ValueError("flag_threshold must be between 0.0 and 1.0")
        self._flag_threshold = flag_threshold
        self._signatures = _COMPILED_SIGNATURES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, prompt: str) -> RuleBasedResult:
        """
        Scan a prompt against all threat signatures.

        Returns:
            RuleBasedResult with risk_score, matches, and audit data.
        """
        t_start = time.perf_counter()

        if not prompt or not prompt.strip():
            return RuleBasedResult(
                prompt=prompt,
                risk_score=0.0,
                is_flagged=False,
                scan_time_ms=0.0,
            )

        matches: list[PatternMatch] = []
        categories_hit: set[AttackCategory] = set()

        for sig in self._signatures:
            for m in sig.regex.finditer(prompt):
                matches.append(
                    PatternMatch(
                        category=sig.category,
                        severity=sig.severity,
                        pattern=sig.pattern,
                        matched_text=m.group(0),
                        start=m.start(),
                        end=m.end(),
                    )
                )
                categories_hit.add(sig.category)

        risk_score = self._compute_risk_score(matches)
        scan_time_ms = (time.perf_counter() - t_start) * 1000

        return RuleBasedResult(
            prompt=prompt,
            risk_score=risk_score,
            is_flagged=risk_score >= self._flag_threshold,
            matches=matches,
            categories_hit=categories_hit,
            scan_time_ms=scan_time_ms,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(matches: list[PatternMatch]) -> float:
        """
        Aggregate match severities into a single 0.0–1.0 risk score.

        Strategy:
          1. Take the maximum single-match severity as the base score.
          2. Apply a diminishing-returns bonus for additional unique categories.
             (more categories = more confident it's an attack, but we cap at 1.0)
          3. Apply a small bonus for raw match count (many hits = more certain).

        This is intentionally conservative — we don't want false positives
        from a single weak match.
        """
        if not matches:
            return 0.0

        # Base: highest individual severity
        max_severity = max(float(m.severity) for m in matches)

        # Category diversity bonus (each new category adds less)
        unique_categories = len({m.category for m in matches})
        diversity_bonus = sum(
            0.08 / (i + 1) for i in range(unique_categories - 1)
        )

        # Match volume bonus (capped)
        volume_bonus = min(len(matches) * 0.02, 0.10)

        raw_score = max_severity + diversity_bonus + volume_bonus
        return round(min(raw_score, 1.0), 4)

    def get_signature_count(self) -> int:
        """Return total number of compiled regex patterns."""
        return len(self._signatures)

    def get_categories(self) -> list[str]:
        """Return all attack category names."""
        return [c.value for c in AttackCategory]