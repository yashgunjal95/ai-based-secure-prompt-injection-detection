# ============================================================
# api/routes/health.py  —  Health check + pipeline status
# ============================================================
from __future__ import annotations
import time
from fastapi import APIRouter, Request
from api.schemas.responses import HealthResponse, PipelineStatusResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    """System health check — confirms all components are reachable."""
    app_state = request.app.state
    pipeline  = getattr(app_state, "pipeline",  None)
    logger    = getattr(app_state, "audit_logger", None)

    components: dict = {}

    # ML Classifier
    ml = getattr(pipeline, "_nodes", None)
    ml = getattr(ml, "_ml", None) if ml else None
    components["ml_classifier"] = {
        "status": "ok" if (ml and ml.is_trained) else "untrained",
        "mode":   ml.mode.value if ml else "unknown",
    }

    # LLM Validator
    llm = getattr(pipeline, "_nodes", None)
    llm = getattr(llm, "_llm", None) if llm else None
    components["llm_validator"] = {
        "status":    "ok"        if (llm and llm.is_available) else "fallback",
        "available": llm.is_available if llm else False,
    }

    # Agent
    agent = getattr(pipeline, "_nodes", None)
    agent = getattr(agent, "_agent", None) if agent else None
    components["agent"] = {
        "status":    "ok"   if (agent and agent.is_available) else "mock",
        "mock_mode": agent.is_mock_mode if agent else True,
    }

    # Audit logger
    components["audit_logger"] = {
        "status":    "ok" if logger else "unavailable",
        "jsonl_path":str(logger.jsonl_path) if logger else "",
    }

    from config import settings
    return HealthResponse(
        status      = "healthy",
        version     = settings.version,
        environment = settings.environment,
        components  = components,
        uptime_s    = round(time.time() - app_state.start_time, 1),
    )


@router.get("/pipeline/status", response_model=PipelineStatusResponse)
async def pipeline_status(request: Request) -> PipelineStatusResponse:
    """Detailed live status of each pipeline component."""
    app_state = request.app.state
    pipeline  = getattr(app_state, "pipeline",  None)
    logger    = getattr(app_state, "audit_logger", None)

    nodes = getattr(pipeline, "_nodes", None)

    ml    = getattr(nodes, "_ml",    None) if nodes else None
    llm   = getattr(nodes, "_llm",   None) if nodes else None
    agent = getattr(nodes, "_agent", None) if nodes else None

    return PipelineStatusResponse(
        ml_classifier = {
            "trained":    ml.is_trained     if ml    else False,
            "mode":       ml.mode.value     if ml    else "unknown",
        },
        llm_validator = {
            "available":  llm.is_available  if llm   else False,
        },
        agent         = {
            "available":  agent.is_available  if agent else False,
            "mock_mode":  agent.is_mock_mode  if agent else True,
            "tool_count": 3,
        },
        log_stats     = logger.stats if logger else {},
    )