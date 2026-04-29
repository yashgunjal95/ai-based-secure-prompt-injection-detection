# ============================================================
# api/main.py  —  FastAPI application factory
# ============================================================
from __future__ import annotations

import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

try:
    from config import settings
except Exception:
    from config_stub import settings  # type: ignore

from core.detection.rule_based      import RuleBasedDetector
from core.detection.ml_classifier   import MLPromptClassifier
from core.detection.llm_validator   import LLMSemanticValidator
from core.detection.decision_engine import DecisionEngine
from core.agent.agent               import SecureAgent
from core.agent.graph               import build_pipeline
from logging_system.audit_logger    import AuditLogger
from logging_system.log_analyzer    import LogAnalyzer

from api.routes import agent      as agent_router
from api.routes import logs       as logs_router
from api.routes import health     as health_router
from api.routes import enterprise as enterprise_router

_FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "="*60)
    print(f"  {settings.project_name}")
    print(f"  v{settings.version} | env={settings.environment}")
    print("="*60)

    app.state.start_time = time.time()

    print("[1/5] Rule-based detector... ", end="", flush=True)
    app.state.rule_detector = RuleBasedDetector()
    print(f"OK ({app.state.rule_detector.get_signature_count()} signatures)")

    print("[2/5] ML classifier... ", end="", flush=True)
    ml = MLPromptClassifier()
    if not ml.is_trained:
        print("training... ", end="", flush=True)
        ml.train(force_lightweight=True)
    print(f"OK (mode={ml.mode.value})")
    app.state.ml_classifier = ml

    print("[3/5] LLM validator... ", end="", flush=True)
    app.state.llm_validator = LLMSemanticValidator()
    status = "live" if app.state.llm_validator.is_available else "fallback"
    print(f"OK (status={status})")

    print("[4/5] Building pipeline... ", end="", flush=True)
    pipeline = build_pipeline(
        rule_detector   = app.state.rule_detector,
        ml_classifier   = app.state.ml_classifier,
        llm_validator   = app.state.llm_validator,
        decision_engine = DecisionEngine(),
        agent           = SecureAgent(),
    )
    app.state.pipeline = pipeline
    print("OK")

    print("[5/5] Audit logger... ", end="", flush=True)
    audit_logger = AuditLogger(enable_stdout=False)
    app.state.audit_logger = audit_logger
    app.state.log_analyzer = LogAnalyzer(audit_logger.jsonl_path)
    print(f"OK -> {audit_logger.jsonl_path}")

    # ── 6. Enterprise Agent ───────────────────────────────────────────────
    print("[6/6] Enterprise agent... ", end="", flush=True)
    try:
        from enterprise.agent.enterprise_agent import EnterpriseAgent
        from enterprise.agent.enterprise_graph import EnterpriseGraph
        enterprise_agent = EnterpriseAgent()
        app.state.enterprise_graph = EnterpriseGraph(enterprise_agent)
        mode = "live" if enterprise_agent.is_available else "mock"
        print(f"OK (mode={mode}, tools={enterprise_agent.tool_count})")
    except Exception as exc:
        print(f"WARNING: {exc} — enterprise agent disabled")
        app.state.enterprise_graph = None

    print("="*60)
    print("  All systems operational.")
    print("  Frontend    -> http://localhost:8000/app")
    print("  Enterprise  -> http://localhost:8000/enterprise")
    print("  Swagger     -> http://localhost:8000/docs")
    print("="*60 + "\n")

    yield

    print("\n[Shutdown] Writing final stats...")
    audit_logger.log_stats()
    print("[Shutdown] Complete.")


def create_app() -> FastAPI:
    app = FastAPI(
        title       = settings.project_name,
        version     = settings.version,
        description = "Three-layer AI prompt injection detection firewall.",
        docs_url    = "/docs",
        redoc_url   = "/redoc",
        lifespan    = lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins  = ["*"],
        allow_methods  = ["GET", "POST"],
        allow_headers  = ["*"],
    )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger = getattr(request.app.state, "audit_logger", None)
        if logger:
            logger.log_error(str(exc), context={"path": str(request.url)})
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc)},
        )

    prefix = "/api/v1"
    app.include_router(health_router.router,     prefix=prefix)
    app.include_router(agent_router.router,      prefix=prefix)
    app.include_router(logs_router.router,       prefix=prefix)
    app.include_router(enterprise_router.router, prefix=prefix)

    @app.get("/enterprise", include_in_schema=False)
    @app.get("/enterprise/", include_in_schema=False)
    async def serve_enterprise():
        index = _FRONTEND / "enterprise.html"
        if index.exists():
            return FileResponse(str(index), media_type="text/html")
        return JSONResponse(status_code=404, content={"error": "Enterprise frontend not found."})

    @app.get("/app", include_in_schema=False)
    @app.get("/app/", include_in_schema=False)
    async def serve_frontend():
        index = _FRONTEND / "index.html"
        if index.exists():
            return FileResponse(str(index), media_type="text/html")
        return JSONResponse(status_code=404, content={"error": "Frontend not found. Place index.html in frontend/ folder."})

    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "name":     settings.project_name,
            "version":  settings.version,
            "frontend": "/app",
            "docs":     "/docs",
            "health":   "/api/v1/health",
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    api_cfg = getattr(settings, "api", None)
    uvicorn.run(
        "api.main:app",
        host    = getattr(api_cfg, "host", "0.0.0.0"),
        port    = getattr(api_cfg, "port", 8000),
        reload  = getattr(api_cfg, "debug", False),
        workers = 1,
    )