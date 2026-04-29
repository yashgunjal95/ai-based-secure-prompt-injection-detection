# ============================================================
# api/routes/logs.py  —  GET /api/v1/logs/*
# ============================================================
from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException, Query
from api.schemas.responses import LogsSummaryResponse, ThreatEntry

router = APIRouter(tags=["logs"])


@router.get("/logs/summary", response_model=LogsSummaryResponse)
async def logs_summary(
    request:     Request,
    since_hours: int = Query(24, ge=1, le=720,
                             description="Time window in hours (default: last 24h)"),
) -> LogsSummaryResponse:
    """Aggregated statistics from the audit log."""
    analyzer = getattr(request.app.state, "log_analyzer", None)
    if not analyzer:
        raise HTTPException(status_code=503, detail="Log analyzer not available.")
    summary = analyzer.summarize(since_hours=since_hours)
    return LogsSummaryResponse(**summary.to_dict())


@router.get("/logs/threats", response_model=list[ThreatEntry])
async def logs_threats(
    request: Request,
    limit:   int = Query(20, ge=1, le=200,
                         description="Max number of threat entries to return"),
) -> list[ThreatEntry]:
    """Recent blocked and sanitized requests."""
    analyzer = getattr(request.app.state, "log_analyzer", None)
    if not analyzer:
        raise HTTPException(status_code=503, detail="Log analyzer not available.")
    return [ThreatEntry(**t) for t in analyzer.get_threats(limit=limit)]


@router.get("/logs/tail")
async def logs_tail(
    request: Request,
    n:       int = Query(20, ge=1, le=100,
                         description="Number of recent entries to return"),
) -> list[dict]:
    """Last N pipeline entries from the audit log."""
    analyzer = getattr(request.app.state, "log_analyzer", None)
    if not analyzer:
        raise HTTPException(status_code=503, detail="Log analyzer not available.")
    return analyzer.tail(n=n)


@router.get("/logs/stats")
async def logs_stats(request: Request) -> dict:
    """Live session statistics from the audit logger."""
    logger = getattr(request.app.state, "audit_logger", None)
    if not logger:
        raise HTTPException(status_code=503, detail="Audit logger not available.")
    return logger.log_stats()