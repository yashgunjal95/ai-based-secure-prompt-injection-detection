# ============================================================
# api/routes/enterprise.py
#
# POST /api/v1/enterprise/chat
#
# Flow:
#   1. Receive prompt from UI
#   2. Run through EXISTING SecurePipeline (unchanged)
#   3. Pass pipeline result to EnterpriseGraph
#   4. EnterpriseGraph either blocks or runs the agent
#   5. Return unified response to UI
#
# The existing /api/v1/agent/run route is NOT modified.
# This is a completely additive new route.
# ============================================================

from __future__ import annotations

import uuid
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

router = APIRouter(tags=["enterprise"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class EnterpriseChatRequest(BaseModel):
    prompt:        str            = Field(..., min_length=1, max_length=4000)
    session_id:    str            = Field(default="enterprise-demo")
    employee_role: str            = Field(default="default")


class LayerScores(BaseModel):
    rule_based:    float
    ml_classifier: float
    llm_validator: float


class SecurityInfo(BaseModel):
    routing:        str           # allow | sanitize | block
    final_score:    float
    layer_scores:   LayerScores
    reasons:        list[str]
    overrides:      list[str]
    rule_matches:   int
    rule_categories:list[str]
    ml_label:       str
    ml_confidence:  float
    llm_verdict:    str
    llm_attack:     str
    blocked:        bool


class ToolCallInfo(BaseModel):
    tool:     str
    input:    str
    output:   str
    exec_ms:  float


class EnterpriseChatResponse(BaseModel):
    request_id:    str
    session_id:    str
    prompt:        str
    response:      str            # Final response to show user
    blocked:       bool
    security:      SecurityInfo
    tool_calls:    list[ToolCallInfo] = []
    steps:         list[str]          = []
    agent_mock:    bool               = False
    total_ms:      float
    errors:        list[str]          = []


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post("/enterprise/chat", response_model=EnterpriseChatResponse, status_code=200)
async def enterprise_chat(
    body: EnterpriseChatRequest,
    request: Request,
) -> EnterpriseChatResponse:
    """
    Submit a prompt to the Secure Enterprise AI Assistant.

    The prompt is first scanned by the full 3-layer security pipeline.
    If cleared, it is routed to the Enterprise Agent (Aria).
    If blocked, a security warning is returned immediately.
    """
    # ── Get pipeline and enterprise graph from app state ──────────────────
    pipeline         = getattr(request.app.state, "pipeline",          None)
    enterprise_graph = getattr(request.app.state, "enterprise_graph",  None)
    logger           = getattr(request.app.state, "audit_logger",      None)

    if not pipeline:
        raise HTTPException(status_code=503, detail="Security pipeline not initialized.")
    if not enterprise_graph:
        raise HTTPException(status_code=503, detail="Enterprise agent not initialized.")

    request_id = str(uuid.uuid4())[:8]
    print(f"[Enterprise] Request {request_id}: {body.prompt[:60]}")

    try:
        # ── STEP 1: Run existing security pipeline ────────────────────────
        print(f"[Enterprise] Step 1: Running security pipeline...")
        pipeline_state = pipeline.run(
            prompt     = body.prompt,
            session_id = body.session_id,
            request_id = request_id,
        )

        # Log via existing audit logger
        if logger:
            logger.log_pipeline_complete(pipeline_state)

        print(f"[Enterprise] Step 1 done: routing={pipeline_state.routing}")
        # ── STEP 2: Extract pipeline results ──────────────────────────────
        dr = pipeline_state.decision_record

        routing          = pipeline_state.routing or "allow"
        final_score      = round(dr.final_score, 4)         if dr else 0.0
        layer_scores_raw = {
            "rule_based":    round(dr.layer_scores.rule_based,    4) if dr else 0.0,
            "ml_classifier": round(dr.layer_scores.ml_classifier, 4) if dr else 0.0,
            "llm_validator": round(dr.layer_scores.llm_validator, 4) if dr else 0.0,
        }
        reasons          = [r.value for r in dr.reasons]         if dr else []
        overrides        = dr.overrides_fired                     if dr else []
        rule_matches     = len(dr.rule_result.matches)            if dr and dr.rule_result else 0
        rule_categories  = [c.value for c in dr.rule_result.categories_hit] if dr and dr.rule_result else []
        ml_label         = dr.ml_result.predicted_label          if dr and dr.ml_result else ""
        ml_confidence    = round(dr.ml_result.confidence, 4)     if dr and dr.ml_result else 0.0
        llm_verdict      = dr.llm_result.verdict.value           if dr and dr.llm_result else ""
        llm_attack       = dr.llm_result.attack_type             if dr and dr.llm_result else ""

        # If routing is sanitize, use the cleaned prompt
        sanitized_prompt = getattr(pipeline_state, "sanitized_prompt", None)

        print(f"[Enterprise] Step 3: Running enterprise graph (routing={routing}, score={final_score:.3f})...")
        # ── STEP 3: Run enterprise graph (handles block gate internally) ──
        ent_state = enterprise_graph.run(
            prompt             = body.prompt,
            security_routing   = routing,
            security_score     = final_score,
            security_reasons   = reasons,
            security_overrides = overrides,
            layer_scores       = layer_scores_raw,
            rule_matches       = rule_matches,
            rule_categories    = rule_categories,
            ml_label           = ml_label,
            ml_confidence      = ml_confidence,
            llm_verdict        = llm_verdict,
            llm_attack         = llm_attack,
            sanitized_prompt   = sanitized_prompt,
            session_id         = body.session_id,
            employee_role      = body.employee_role,
        )

        print(f"[Enterprise] Step 3 done: blocked={ent_state.blocked}, output_len={len(ent_state.final_output)}, errors={ent_state.errors}")
        # ── STEP 4: Build response ─────────────────────────────────────────
        tool_calls_out = [
            ToolCallInfo(
                tool    = tc["tool"],
                input   = tc["input"],
                output  = tc["output"],
                exec_ms = tc.get("exec_ms", 0.0),
            )
            for tc in (ent_state.tool_calls or [])
        ]

        return EnterpriseChatResponse(
            request_id  = request_id,
            session_id  = body.session_id,
            prompt      = body.prompt,
            response    = ent_state.final_output,
            blocked     = ent_state.blocked,
            security    = SecurityInfo(
                routing         = routing,
                final_score     = final_score,
                layer_scores    = LayerScores(**layer_scores_raw),
                reasons         = reasons,
                overrides       = overrides,
                rule_matches    = rule_matches,
                rule_categories = rule_categories,
                ml_label        = ml_label,
                ml_confidence   = ml_confidence,
                llm_verdict     = llm_verdict,
                llm_attack      = llm_attack,
                blocked         = ent_state.blocked,
            ),
            tool_calls  = tool_calls_out,
            steps       = ent_state.steps or [],
            agent_mock  = ent_state.agent_mock_mode,
            total_ms    = round(ent_state.total_ms, 2),
            errors      = ent_state.errors or [],
        )

    except Exception as exc:
        import traceback
        full_error = traceback.format_exc()
        if logger:
            logger.log_error(str(exc), request_id=request_id)
        # Return structured error response instead of crashing
        # so the UI shows the actual error for debugging
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={
                "error":      str(exc),
                "traceback":  full_error,
                "request_id": request_id,
                "hint":       "Check server terminal for full traceback",
            }
        )