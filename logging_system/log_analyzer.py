# ============================================================
# logging_system/log_analyzer.py
#
# Log Analyzer — Query and summarize the JSONL audit log.
#
# Provides:
#   - Summary statistics (totals, rates, top attack categories)
#   - Time-windowed filtering
#   - Threat-only views
#   - Per-session drill-down
#   - Export to dict for API endpoint /api/v1/logs/summary
# ============================================================

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterator

_ROOT = str(Path(__file__).resolve().parents[2])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class LogSummary:
    """Aggregated statistics from the audit log."""
    total_requests:     int
    allowed:            int
    sanitized:          int
    blocked:            int
    error_count:        int
    block_rate:         float               # blocked / total
    threat_rate:        float               # (blocked + sanitized) / total
    avg_final_score:    float
    avg_total_ms:       float
    top_attack_categories: list[tuple[str, int]]
    top_attack_types:      list[tuple[str, int]]
    top_reasons:           list[tuple[str, int]]
    recent_blocks:         list[dict]       # last 5 blocked prompts
    time_range:            dict[str, str]   # first_seen / last_seen

    def to_dict(self) -> dict:
        return {
            "total_requests":     self.total_requests,
            "decisions": {
                "allowed":   self.allowed,
                "sanitized": self.sanitized,
                "blocked":   self.blocked,
            },
            "rates": {
                "block_rate":  round(self.block_rate,  4),
                "threat_rate": round(self.threat_rate, 4),
            },
            "performance": {
                "avg_final_score": round(self.avg_final_score, 4),
                "avg_total_ms":    round(self.avg_total_ms,    2),
            },
            "top_attack_categories": self.top_attack_categories,
            "top_attack_types":      self.top_attack_types,
            "top_decision_reasons":  self.top_reasons,
            "recent_blocks":         self.recent_blocks,
            "time_range":            self.time_range,
            "error_count":           self.error_count,
        }


# ---------------------------------------------------------------------------
# Log Analyzer
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """
    Query and analyze the JSONL audit log produced by AuditLogger.

    Usage:
        analyzer = LogAnalyzer(Path("logs/audit.jsonl"))
        summary  = analyzer.summarize()
        threats  = analyzer.get_threats(limit=20)
        session  = analyzer.get_session("abc123")
    """

    def __init__(self, jsonl_path: Path) -> None:
        self._path = jsonl_path

    # ------------------------------------------------------------------
    # Core Reader
    # ------------------------------------------------------------------

    def _read_entries(
        self,
        event_type: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> Iterator[dict]:
        """
        Stream entries from the JSONL log.
        Applies optional filters: event_type, since (datetime), limit.
        """
        if not self._path.exists():
            return

        count = 0
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Filter by event type
                if event_type and entry.get("event_type") != event_type:
                    continue

                # Filter by time window
                if since:
                    ts_str = entry.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts < since:
                            continue
                    except (ValueError, AttributeError):
                        pass

                yield entry
                count += 1
                if limit and count >= limit:
                    break

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summarize(
        self,
        since_hours: int | None = None,
    ) -> LogSummary:
        """
        Generate a full statistical summary of the audit log.

        Args:
            since_hours: If set, only include entries from last N hours
        """
        since = None
        if since_hours:
            since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        total = allowed = sanitized = blocked = errors = 0
        scores:        list[float] = []
        timings:       list[float] = []
        attack_cats:   Counter     = Counter()
        attack_types:  Counter     = Counter()
        reasons:       Counter     = Counter()
        recent_blocks: list[dict]  = []
        timestamps:    list[str]   = []

        for entry in self._read_entries(
            event_type="pipeline_complete", since=since
        ):
            total += 1
            routing = entry.get("routing", "")
            ts      = entry.get("timestamp", "")

            if ts:
                timestamps.append(ts)

            if routing == "allow":
                allowed += 1
            elif routing == "sanitize":
                sanitized += 1
            elif routing == "block":
                blocked += 1

            if entry.get("errors"):
                errors += 1

            # Collect scores and timings
            dec = entry.get("decision", {})
            if dec:
                if "final_score" in dec:
                    scores.append(float(dec["final_score"]))

                # Attack categories from rule layer
                for cat in dec.get("rule_categories", []):
                    if cat and cat != "none":
                        attack_cats[cat] += 1

                # LLM attack type
                llm_attack = dec.get("llm_attack", "")
                if llm_attack and llm_attack not in ("none", "unknown", ""):
                    attack_types[llm_attack] += 1

                # Decision reasons
                for reason in dec.get("reasons", []):
                    reasons[reason] += 1

            # Node timing — total from node_timings sum
            node_t = entry.get("node_timings", {})
            if node_t:
                timings.append(sum(node_t.values()))

            # Track recent blocks
            if routing == "block":
                recent_blocks.append({
                    "timestamp":     ts,
                    "request_id":    entry.get("request_id", ""),
                    "prompt":        entry.get("prompt_preview", ""),
                    "final_score":   dec.get("final_score", 0) if dec else 0,
                    "reasons":       dec.get("reasons", []) if dec else [],
                })

        # Keep only last 5 blocks
        recent_blocks = recent_blocks[-5:]

        block_rate  = blocked  / total if total else 0.0
        threat_rate = (blocked + sanitized) / total if total else 0.0
        avg_score   = sum(scores)  / len(scores)  if scores  else 0.0
        avg_ms      = sum(timings) / len(timings) if timings else 0.0

        return LogSummary(
            total_requests       = total,
            allowed              = allowed,
            sanitized            = sanitized,
            blocked              = blocked,
            error_count          = errors,
            block_rate           = block_rate,
            threat_rate          = threat_rate,
            avg_final_score      = avg_score,
            avg_total_ms         = avg_ms,
            top_attack_categories= attack_cats.most_common(5),
            top_attack_types     = attack_types.most_common(5),
            top_reasons          = reasons.most_common(5),
            recent_blocks        = recent_blocks,
            time_range           = {
                "first_seen": timestamps[0]  if timestamps else "N/A",
                "last_seen":  timestamps[-1] if timestamps else "N/A",
            },
        )

    def get_threats(self, limit: int = 50) -> list[dict]:
        """Return the most recent blocked + sanitized requests."""
        threats = []
        for entry in self._read_entries(event_type="pipeline_complete"):
            if entry.get("routing") in ("block", "sanitize"):
                threats.append({
                    "timestamp":   entry.get("timestamp"),
                    "request_id":  entry.get("request_id"),
                    "routing":     entry.get("routing"),
                    "prompt":      entry.get("prompt_preview"),
                    "final_score": entry.get("decision", {}).get("final_score"),
                    "reasons":     entry.get("decision", {}).get("reasons", []),
                    "attack_type": entry.get("decision", {}).get("llm_attack"),
                    "categories":  entry.get("decision", {}).get("rule_categories", []),
                })
        return threats[-limit:]

    def get_session(self, session_id: str) -> list[dict]:
        """Return all log entries for a specific session."""
        return [
            e for e in self._read_entries()
            if e.get("session_id") == session_id
        ]

    def get_request(self, request_id: str) -> list[dict]:
        """Return all log entries for a specific request."""
        return [
            e for e in self._read_entries()
            if e.get("request_id") == request_id
        ]

    def tail(self, n: int = 20) -> list[dict]:
        """Return the last N pipeline_complete entries."""
        entries = list(self._read_entries(event_type="pipeline_complete"))
        return entries[-n:]

    def count_by_routing(self) -> dict[str, int]:
        """Quick tally of decisions by routing type."""
        counts: dict[str, int] = defaultdict(int)
        for e in self._read_entries(event_type="pipeline_complete"):
            counts[e.get("routing", "unknown")] += 1
        return dict(counts)

    def export_threats_csv(self, output_path: Path) -> int:
        """Export all threat entries to a CSV file. Returns row count."""
        import csv
        threats = self.get_threats(limit=10000)
        if not threats:
            return 0
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=threats[0].keys())
            writer.writeheader()
            writer.writerows(threats)
        return len(threats)