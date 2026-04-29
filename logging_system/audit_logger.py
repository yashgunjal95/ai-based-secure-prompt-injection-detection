# ============================================================
# logging_system/audit_logger.py
#
# Audit Logger — Structured persistent logging for every
# pipeline decision made by the Secure Agent Firewall.
#
# Two output streams:
#   1. JSONL audit log  — one JSON object per line, append-only
#      → logs/audit.jsonl   (machine-readable, permanent record)
#   2. Human log        — coloured, formatted via loguru
#      → logs/audit.log + stdout
#
# Every log entry is a self-contained record — no foreign keys,
# no joins needed to reconstruct what happened to a prompt.
# ============================================================

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

# ── Loguru (guarded) ─────────────────────────────────────────────────────────
try:
    from loguru import logger as _loguru_logger
    _LOGURU_AVAILABLE = True
except ImportError:
    _LOGURU_AVAILABLE = False

# ── Project imports ──────────────────────────────────────────────────────────
_ROOT = str(Path(__file__).resolve().parents[2])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from config import settings
except Exception:
    from config_stub import settings  # type: ignore

from core.detection.decision_engine import DecisionRecord, Decision
from core.agent.agent import AgentResponse


# ---------------------------------------------------------------------------
# Log Entry Types
# ---------------------------------------------------------------------------

class LogEventType(str, Enum):
    PIPELINE_START    = "pipeline_start"
    LAYER_1_RESULT    = "layer_1_result"
    LAYER_2_RESULT    = "layer_2_result"
    LAYER_3_RESULT    = "layer_3_result"
    DECISION          = "decision"
    AGENT_RESPONSE    = "agent_response"
    PIPELINE_COMPLETE = "pipeline_complete"
    ERROR             = "error"
    SYSTEM_START      = "system_start"
    SYSTEM_STATS      = "system_stats"


@dataclass
class AuditEntry:
    """
    A single structured audit log entry.
    Serializes to JSON for the JSONL log file.
    """
    event_type:    LogEventType
    timestamp:     str                    # ISO-8601 UTC
    timestamp_ms:  float                  # Unix epoch milliseconds
    request_id:    str
    session_id:    str
    data:          dict[str, Any]
    severity:      str  = "INFO"          # INFO | WARNING | CRITICAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type":   self.event_type.value,
            "timestamp":    self.timestamp,
            "timestamp_ms": self.timestamp_ms,
            "request_id":   self.request_id,
            "session_id":   self.session_id,
            "severity":     self.severity,
            **self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Persistent structured audit logger for the Secure Agent Firewall.

    Writes two output streams simultaneously:
      - JSONL file  (machine-readable, append-only)
      - Human log   (via loguru or stdlib logging as fallback)

    Usage:
        logger = AuditLogger()
        logger.log_pipeline_complete(state)
        logger.log_decision(decision_record, request_id, session_id)
    """

    def __init__(
        self,
        log_dir: Path | None = None,
        log_level: str = "INFO",
        enable_stdout: bool = True,
    ) -> None:
        log_cfg  = getattr(settings, "logging", None)
        base_dir = Path(_ROOT)

        self._log_dir = log_dir or (
            Path(getattr(log_cfg, "file_path", base_dir / "logs" / "audit.log")).parent
        )
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self._jsonl_path  = self._log_dir / "audit.jsonl"
        self._human_path  = self._log_dir / "audit.log"
        self._log_level   = log_level
        self._enable_stdout = enable_stdout

        # Session-level stats counters
        self._stats = {
            "total":    0,
            "allowed":  0,
            "sanitized":0,
            "blocked":  0,
            "errors":   0,
        }

        self._setup_human_logger()
        self._write_system_start()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup_human_logger(self) -> None:
        """Configure loguru (or stdlib fallback) for human-readable output."""
        if _LOGURU_AVAILABLE:
            _loguru_logger.remove()   # remove default handler

            # File handler
            _loguru_logger.add(
                str(self._human_path),
                level      = self._log_level,
                format     = (
                    "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
                    "{level: <8} | {message}"
                ),
                rotation   = getattr(
                    getattr(settings, "logging", None), "rotation", "10 MB"
                ),
                retention  = getattr(
                    getattr(settings, "logging", None), "retention", "30 days"
                ),
                encoding   = "utf-8",
            )

            # Stdout handler (coloured)
            if self._enable_stdout:
                _loguru_logger.add(
                    sys.stdout,
                    level  = self._log_level,
                    format = (
                        "<green>{time:HH:mm:ss}</green> | "
                        "<level>{level: <8}</level> | "
                        "<cyan>{message}</cyan>"
                    ),
                    colorize = True,
                )
            self._logger = _loguru_logger
        else:
            import logging
            logging.basicConfig(
                level   = self._log_level,
                format  = "%(asctime)s | %(levelname)-8s | %(message)s",
                handlers= [
                    logging.FileHandler(str(self._human_path), encoding="utf-8"),
                    *([ logging.StreamHandler(sys.stdout) ] if self._enable_stdout else []),
                ],
            )
            self._logger = logging.getLogger("audit")

    def _write_system_start(self) -> None:
        self._log_event(AuditEntry(
            event_type   = LogEventType.SYSTEM_START,
            timestamp    = _now_iso(),
            timestamp_ms = _now_ms(),
            request_id   = "SYSTEM",
            session_id   = "SYSTEM",
            severity     = "INFO",
            data         = {
                "message":         "Secure Agent Firewall started",
                "jsonl_log":       str(self._jsonl_path),
                "human_log":       str(self._human_path),
                "loguru_available":_LOGURU_AVAILABLE,
            },
        ))

    # ------------------------------------------------------------------
    # Public Logging API
    # ------------------------------------------------------------------

    def log_pipeline_complete(
        self,
        state: Any,               # PipelineState — avoid circular import
    ) -> None:
        """
        Log the complete result of one pipeline run.
        This is the primary logging call — covers everything.
        """
        request_id = getattr(state, "request_id", "unknown")
        session_id = getattr(state, "session_id", "")
        routing    = getattr(state, "routing", "unknown")
        dr         = getattr(state, "decision_record", None)
        ar         = getattr(state, "agent_response", None)
        errors     = getattr(state, "errors", [])

        # Update session stats
        self._stats["total"] += 1
        if routing == "allow":
            self._stats["allowed"]   += 1
        elif routing == "sanitize":
            self._stats["sanitized"] += 1
        elif routing == "block":
            self._stats["blocked"]   += 1
        if errors:
            self._stats["errors"]    += 1

        # Determine severity for log colouring
        severity = "INFO"
        if routing == "block":
            severity = "WARNING"
        if errors:
            severity = "WARNING"

        # Build payload
        payload: dict[str, Any] = {
            "routing":         routing,
            "prompt_preview":  _truncate(getattr(state, "original_prompt", ""), 80),
            "prompt_length":   len(getattr(state, "original_prompt", "")),
            "completed":       getattr(state, "completed", False),
            "node_timings":    getattr(state, "node_timings", {}),
            "errors":          errors,
        }

        if dr:
            payload["decision"] = {
                "decision_id":   dr.decision_id,
                "final_score":   round(dr.final_score, 4),
                "weighted_score":round(dr.weighted_score, 4),
                "reasons":       [r.value for r in dr.reasons],
                "overrides":     dr.overrides_fired,
                "layer_scores":  {
                    "rule_based":    round(dr.layer_scores.rule_based, 4),
                    "ml_classifier": round(dr.layer_scores.ml_classifier, 4),
                    "llm_validator": round(dr.layer_scores.llm_validator, 4),
                },
                "rule_matches":  len(dr.rule_result.matches) if dr.rule_result else 0,
                "rule_categories":[c.value for c in dr.rule_result.categories_hit]
                                    if dr.rule_result else [],
                "ml_label":      dr.ml_result.predicted_label if dr.ml_result else "",
                "llm_verdict":   dr.llm_result.verdict.value  if dr.llm_result else "",
                "llm_attack":    dr.llm_result.attack_type    if dr.llm_result else "",
            }

        if ar and routing != "block":
            payload["agent"] = {
                "success":    ar.success,
                "tools_used": [t["tool"] for t in ar.tool_calls],
                "step_count": len(ar.steps),
                "exec_ms":    ar.execution_ms,
                "output_preview": _truncate(ar.output, 100),
            }

        entry = AuditEntry(
            event_type   = LogEventType.PIPELINE_COMPLETE,
            timestamp    = _now_iso(),
            timestamp_ms = _now_ms(),
            request_id   = request_id,
            session_id   = session_id,
            severity     = severity,
            data         = payload,
        )

        self._log_event(entry)

        # Human-readable one-liner
        score_str = f"score={dr.final_score:.3f}" if dr else "score=N/A"
        tools_str = ""
        if ar and ar.tool_calls:
            tools_str = f" | tools={[t['tool'] for t in ar.tool_calls]}"
        self._human_log(
            severity,
            f"[{routing.upper():8s}] req={request_id} | {score_str}"
            f" | prompt='{_truncate(getattr(state,'original_prompt',''), 45)}'"
            f"{tools_str}"
        )

    def log_decision(
        self,
        record:     DecisionRecord,
        request_id: str = "",
        session_id: str = "",
    ) -> None:
        """Log a standalone DecisionRecord (used when pipeline not available)."""
        severity = "WARNING" if record.is_threat else "INFO"
        entry = AuditEntry(
            event_type   = LogEventType.DECISION,
            timestamp    = _now_iso(),
            timestamp_ms = _now_ms(),
            request_id   = request_id or record.decision_id[:8],
            session_id   = session_id,
            severity     = severity,
            data         = record.to_dict(),
        )
        self._log_event(entry)

    def log_error(
        self,
        error:      str,
        context:    dict | None = None,
        request_id: str = "",
        session_id: str = "",
    ) -> None:
        """Log a pipeline error."""
        self._stats["errors"] += 1
        entry = AuditEntry(
            event_type   = LogEventType.ERROR,
            timestamp    = _now_iso(),
            timestamp_ms = _now_ms(),
            request_id   = request_id,
            session_id   = session_id,
            severity     = "CRITICAL",
            data         = {"error": error, "context": context or {}},
        )
        self._log_event(entry)
        self._human_log("ERROR", f"Pipeline error | req={request_id} | {error}")

    def log_stats(self) -> dict[str, Any]:
        """Write current session statistics to both logs and return them."""
        stats = {**self._stats, "timestamp": _now_iso()}
        entry = AuditEntry(
            event_type   = LogEventType.SYSTEM_STATS,
            timestamp    = _now_iso(),
            timestamp_ms = _now_ms(),
            request_id   = "SYSTEM",
            session_id   = "SYSTEM",
            severity     = "INFO",
            data         = stats,
        )
        self._log_event(entry)
        self._human_log(
            "INFO",
            f"[STATS] total={stats['total']} | "
            f"allowed={stats['allowed']} | "
            f"sanitized={stats['sanitized']} | "
            f"blocked={stats['blocked']} | "
            f"errors={stats['errors']}"
        )
        return stats

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats}

    @property
    def jsonl_path(self) -> Path:
        return self._jsonl_path

    @property
    def log_dir(self) -> Path:
        return self._log_dir

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log_event(self, entry: AuditEntry) -> None:
        """Append a single entry to the JSONL audit log (atomic write)."""
        try:
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(entry.to_json() + "\n")
        except OSError as exc:
            # Never crash the pipeline because logging failed
            print(f"[AuditLogger] JSONL write error: {exc}", file=sys.stderr)

    def _human_log(self, level: str, message: str) -> None:
        """Write to the human-readable log stream."""
        try:
            if _LOGURU_AVAILABLE:
                getattr(self._logger, level.lower(), self._logger.info)(message)
            else:
                getattr(self._logger, level.lower(),
                        self._logger.info)(message)
        except Exception:
            pass   # logging must never crash the application


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _now_ms() -> float:
    return time.time() * 1000

def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


# ---------------------------------------------------------------------------
# Singleton helper
# ---------------------------------------------------------------------------

_default_logger: AuditLogger | None = None

def get_logger(enable_stdout: bool = False) -> AuditLogger:
    """
    Return (or create) the module-level default AuditLogger.
    Used by the FastAPI layer to get a shared instance.
    """
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger(enable_stdout=enable_stdout)
    return _default_logger