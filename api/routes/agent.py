# ============================================================
# api/routes/agent.py  —  POST /api/v1/agent/run
# ============================================================
from __future__ import annotations
import uuid
from fastapi import APIRouter, Request, HTTPException
from api.schemas.requests  import RunAgentRequest
from api.schemas.responses import RunAgentResponse, DecisionOut, AgentOut, LayerScoresOut

router = APIRouter(tags=["agent"])


@router.post("/agent/run", response_model=RunAgentResponse, status_code=200)
async def run_agent(body: RunAgentRequest, request: Request) -> RunAgentResponse:
    """
    Submit a prompt through the full Secure Agent Pipeline.

    The prompt passes through:
      1. Rule-based detector   (Layer 1)
      2. ML classifier         (Layer 2)
      3. LLM semantic validator(Layer 3)
      4. Decision Engine
      5. SecureAgent (only if decision = allow or sanitize)

    Returns the routing decision, scores, and agent response.
    """
    pipeline = getattr(request.app.state, "pipeline", None)
    logger   = getattr(request.app.state, "audit_logger", None)

    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized.")

    request_id = str(uuid.uuid4())[:8]

    try:
        state = pipeline.run(
            prompt     = body.prompt,
            session_id = body.session_id,
            request_id = request_id,
        )

        # Log every request
        if logger:
            logger.log_pipeline_complete(state)

        # Build structured response
        dr  = state.decision_record
        ar  = state.agent_response

        decision_out = None
        if dr:
            decision_out = DecisionOut(
                decision_id     = dr.decision_id,
                final_score     = round(dr.final_score,    4),
                weighted_score  = round(dr.weighted_score, 4),
                decision        = dr.decision.value,
                is_threat       = dr.is_threat,
                reasons         = [r.value for r in dr.reasons],
                overrides_fired = dr.overrides_fired,
                layer_scores    = LayerScoresOut(
                    rule_based    = round(dr.layer_scores.rule_based,    4),
                    ml_classifier = round(dr.layer_scores.ml_classifier, 4),
                    llm_validator = round(dr.layer_scores.llm_validator, 4),
                ),
                rule_matches    = len(dr.rule_result.matches)
                                  if dr.rule_result else 0,
                rule_categories = [c.value for c in dr.rule_result.categories_hit]
                                  if dr.rule_result else [],
                ml_label        = dr.ml_result.predicted_label if dr.ml_result else "",
                ml_confidence   = round(dr.ml_result.confidence, 4) if dr.ml_result else 0.0,
                llm_verdict     = dr.llm_result.verdict.value
                                  if dr.llm_result else "",
                llm_attack      = dr.llm_result.attack_type
                                  if dr.llm_result else "",
            )

        agent_out = None
        if ar and state.routing != "block":
            agent_out = AgentOut(
                output     = ar.output,
                tools_used = [t["tool"] for t in ar.tool_calls],
                step_count = len(ar.steps),
                exec_ms    = ar.execution_ms,
                success    = ar.success,
            )

        return RunAgentResponse(
            request_id   = request_id,
            session_id   = body.session_id,
            routing      = state.routing,
            completed    = state.completed,
            final_output = state.final_output,
            decision     = decision_out,
            agent        = agent_out,
            node_timings = state.node_timings,
            total_ms     = round(state.total_ms, 2),
            errors       = state.errors,
        )

    except Exception as exc:
        if logger:
            logger.log_error(str(exc), request_id=request_id)
        raise HTTPException(status_code=500, detail=f"Pipeline error: {exc}")