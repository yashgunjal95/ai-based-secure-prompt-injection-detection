# ============================================================
# core/agent/graph.py
#
# LangGraph Execution Flow — Secure Agent Pipeline
#
# Implements the full prompt-to-response pipeline as a
# stateful directed graph with conditional routing.
#
# Graph nodes:
#   layer_1_scan   → Rule-based detection
#   layer_2_scan   → ML classifier
#   layer_3_scan   → LLM semantic validator
#   decide         → Decision Engine aggregation
#   handle_block   → Reject malicious prompt
#   handle_sanitize→ Clean + forward to agent
#   handle_allow   → Forward clean prompt to agent
#   run_agent      → Execute SecureAgent
#
# State flows left→right, never backwards.
# Conditional edges branch ONLY at the decide node.
# ============================================================

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

import sys
_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from config import settings
except Exception:
    from config_stub import settings  # type: ignore

# ── LangGraph imports (guarded) ──────────────────────────────────────────────
try:
    from langgraph.graph import StateGraph, END
    from typing import TypedDict
    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False
    # Minimal shim so the module still runs without langgraph installed
    class TypedDict:  # type: ignore
        pass
    END = "__end__"

# ── Internal imports ─────────────────────────────────────────────────────────
from core.detection.rule_based    import RuleBasedDetector,    RuleBasedResult
from core.detection.ml_classifier import MLPromptClassifier,   MLClassifierResult
from core.detection.llm_validator import LLMSemanticValidator, LLMValidatorResult
from core.detection.decision_engine import (
    DecisionEngine, DecisionRecord, Decision,
)
from core.agent.agent import SecureAgent, AgentResponse


# ---------------------------------------------------------------------------
# Pipeline State
# ---------------------------------------------------------------------------
# This is the single mutable object that flows through every node.
# Each node reads from it and writes its results back into it.
# Using a dataclass (not TypedDict) so it works with/without langgraph.

@dataclass
class PipelineState:
    """
    Mutable state object passed between all graph nodes.

    Populated progressively as the prompt moves through the pipeline:
      START → layer1 → layer2 → layer3 → decide → [block|sanitize|allow] → agent → END
    """
    # ── Input ────────────────────────────────────────────────────────────
    original_prompt:   str
    session_id:        str  = ""
    request_id:        str  = ""

    # ── Layer results (set by each scan node) ────────────────────────────
    rule_result:       Optional[RuleBasedResult]    = None
    ml_result:         Optional[MLClassifierResult] = None
    llm_result:        Optional[LLMValidatorResult] = None

    # ── Decision (set by decide node) ────────────────────────────────────
    decision_record:   Optional[DecisionRecord]     = None
    routing:           str                          = ""   # "allow"|"sanitize"|"block"

    # ── Agent execution (set by run_agent node) ──────────────────────────
    agent_response:    Optional[AgentResponse]      = None
    final_prompt:      str                          = ""   # sanitized or original

    # ── Pipeline metadata ────────────────────────────────────────────────
    pipeline_start_ms: float                        = 0.0
    node_timings:      dict[str, float]             = field(default_factory=dict)
    errors:            list[str]                    = field(default_factory=list)
    completed:         bool                         = False

    @property
    def total_ms(self) -> float:
        if self.pipeline_start_ms:
            return (time.perf_counter() - self.pipeline_start_ms) * 1000
        return 0.0

    @property
    def final_output(self) -> str:
        """The user-facing response regardless of path taken."""
        if self.routing == "block":
            return (
                "⛔ Request blocked: Your prompt was identified as a potential "
                "prompt injection attack and has been rejected for security reasons."
            )
        if self.agent_response:
            return self.agent_response.output
        return "No response generated."

    def to_dict(self) -> dict[str, Any]:
        """Serialisable summary for API responses and audit logs."""
        return {
            "request_id":    self.request_id,
            "session_id":    self.session_id,
            "routing":       self.routing,
            "completed":     self.completed,
            "final_output":  self.final_output,
            "original_prompt": self.original_prompt,
            "final_prompt":  self.final_prompt,
            "decision":      self.decision_record.to_dict() if self.decision_record else None,
            "agent":         self.agent_response.to_dict() if self.agent_response else None,
            "node_timings":  {k: round(v, 2) for k, v in self.node_timings.items()},
            "errors":        self.errors,
            "total_ms":      round(self.total_ms, 2),
        }


# ---------------------------------------------------------------------------
# Graph Nodes
# ---------------------------------------------------------------------------

class PipelineNodes:
    """
    All graph node implementations as methods.
    Each node receives the full PipelineState, mutates it, and returns it.
    """

    def __init__(
        self,
        rule_detector:  RuleBasedDetector,
        ml_classifier:  MLPromptClassifier,
        llm_validator:  LLMSemanticValidator,
        decision_engine: DecisionEngine,
        agent:          SecureAgent,
    ) -> None:
        self._rules    = rule_detector
        self._ml       = ml_classifier
        self._llm      = llm_validator
        self._engine   = decision_engine
        self._agent    = agent

    # ── Node 1: Layer 1 — Rule-Based Scan ────────────────────────────────

    def layer_1_scan(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        try:
            state.rule_result = self._rules.scan(state.original_prompt)
        except Exception as exc:
            state.errors.append(f"layer_1_error: {exc}")
            # Fail-safe: produce a neutral result so pipeline continues
            from core.detection.rule_based import RuleBasedResult
            state.rule_result = RuleBasedResult(
                prompt=state.original_prompt,
                risk_score=0.5,
                is_flagged=True,
            )
        state.node_timings["layer_1"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 2: Layer 2 — ML Classifier ──────────────────────────────────

    def layer_2_scan(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        try:
            state.ml_result = self._ml.predict(state.original_prompt)
        except Exception as exc:
            state.errors.append(f"layer_2_error: {exc}")
            from core.detection.ml_classifier import MLClassifierResult, ClassifierMode
            state.ml_result = MLClassifierResult(
                prompt=state.original_prompt,
                risk_score=0.5,
                predicted_label="unknown",
                confidence=0.0,
                model_mode=ClassifierMode.UNTRAINED,
                inference_time_ms=0.0,
            )
        state.node_timings["layer_2"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 3: Layer 3 — LLM Semantic Validator ─────────────────────────

    def layer_3_scan(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        try:
            state.llm_result = self._llm.validate(state.original_prompt)
        except Exception as exc:
            state.errors.append(f"layer_3_error: {exc}")
            from core.detection.llm_validator import LLMValidatorResult, LLMVerdict
            state.llm_result = LLMValidatorResult(
                prompt=state.original_prompt,
                risk_score=0.5,
                verdict=LLMVerdict.ERROR,
                attack_type="unknown",
                reasoning="Layer 3 error — conservative fallback.",
                recommendation="sanitize",
                confidence=0.0,
                raw_response="",
                validation_time_ms=0.0,
                error=str(exc),
            )
        state.node_timings["layer_3"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 4: Decision Engine ───────────────────────────────────────────

    def decide(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        try:
            state.decision_record = self._engine.decide(
                prompt      = state.original_prompt,
                rule_result  = state.rule_result,
                ml_result    = state.ml_result,
                llm_result   = state.llm_result,
                t_pipeline_start = state.pipeline_start_ms,
            )
            state.routing = state.decision_record.decision.value
        except Exception as exc:
            state.errors.append(f"decide_error: {exc}")
            state.routing = "block"   # fail-safe
        state.node_timings["decide"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 5a: Handle Block ─────────────────────────────────────────────

    def handle_block(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        # Log the blocked attempt — no agent execution
        state.final_prompt = ""
        state.completed    = True
        state.node_timings["handle_block"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 5b: Handle Sanitize ──────────────────────────────────────────

    def handle_sanitize(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        # Use the sanitized prompt produced by Decision Engine
        if state.decision_record and state.decision_record.sanitized_prompt:
            state.final_prompt = state.decision_record.sanitized_prompt
        else:
            state.final_prompt = state.original_prompt
        state.node_timings["handle_sanitize"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 5c: Handle Allow ─────────────────────────────────────────────

    def handle_allow(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        state.final_prompt = state.original_prompt
        state.node_timings["handle_allow"] = (time.perf_counter() - t) * 1000
        return state

    # ── Node 6: Run Agent ─────────────────────────────────────────────────

    def run_agent(self, state: PipelineState) -> PipelineState:
        t = time.perf_counter()
        try:
            state.agent_response = self._agent.run(state.final_prompt)
        except Exception as exc:
            state.errors.append(f"agent_error: {exc}")
            state.agent_response = AgentResponse(
                prompt=state.final_prompt,
                output=f"Agent execution error: {exc}",
                success=False,
                error=str(exc),
            )
        state.completed = True
        state.node_timings["run_agent"] = (time.perf_counter() - t) * 1000
        return state

    # ── Conditional edge router ───────────────────────────────────────────

    @staticmethod
    def route_after_decision(
        state: PipelineState,
    ) -> Literal["handle_block", "handle_sanitize", "handle_allow"]:
        """
        LangGraph conditional edge function.
        Returns the name of the next node based on the routing decision.
        """
        r = state.routing
        if r == Decision.BLOCK.value:
            return "handle_block"
        elif r == Decision.SANITIZE.value:
            return "handle_sanitize"
        else:
            return "handle_allow"


# ---------------------------------------------------------------------------
# Pipeline Graph Builder
# ---------------------------------------------------------------------------

def build_pipeline(
    rule_detector:   RuleBasedDetector   | None = None,
    ml_classifier:   MLPromptClassifier  | None = None,
    llm_validator:   LLMSemanticValidator| None = None,
    decision_engine: DecisionEngine      | None = None,
    agent:           SecureAgent         | None = None,
) -> "SecurePipeline":
    """
    Factory function — instantiates all components and returns
    a ready-to-use SecurePipeline.
    """
    return SecurePipeline(
        rule_detector   = rule_detector   or RuleBasedDetector(),
        ml_classifier   = ml_classifier   or MLPromptClassifier(),
        llm_validator   = llm_validator   or LLMSemanticValidator(),
        decision_engine = decision_engine or DecisionEngine(),
        agent           = agent           or SecureAgent(),
    )


# ---------------------------------------------------------------------------
# SecurePipeline — Main Entry Point
# ---------------------------------------------------------------------------

class SecurePipeline:
    """
    The complete Secure Agent Pipeline.

    Orchestrates all components in sequence:
        Prompt → Layer1 → Layer2 → Layer3 → Decision → [Block|Sanitize|Allow] → Agent

    Supports two execution modes:
        GRAPH MODE  — Uses LangGraph StateGraph (preferred)
        LINEAR MODE — Falls back to direct sequential execution if LangGraph
                      is not installed (identical results, no graph overhead)

    Usage:
        pipeline = build_pipeline()
        result   = pipeline.run("What is the capital of France?")
        print(result.final_output)
    """

    def __init__(
        self,
        rule_detector:   RuleBasedDetector,
        ml_classifier:   MLPromptClassifier,
        llm_validator:   LLMSemanticValidator,
        decision_engine: DecisionEngine,
        agent:           SecureAgent,
    ) -> None:
        self._nodes = PipelineNodes(
            rule_detector, ml_classifier,
            llm_validator, decision_engine, agent,
        )
        self._graph = None

        if _LANGGRAPH_AVAILABLE:
            self._graph = self._build_graph()
            print("[SecurePipeline] LangGraph graph compiled successfully.")
        else:
            print("[SecurePipeline] LangGraph not installed — linear mode active.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        prompt:     str,
        session_id: str = "",
        request_id: str = "",
    ) -> PipelineState:
        """
        Run a prompt through the full secure pipeline.

        Args:
            prompt:     Raw user prompt (untrusted)
            session_id: Optional session identifier for logging
            request_id: Optional request identifier for logging

        Returns:
            PipelineState with all layer results, decision, and agent response
        """
        import uuid
        state = PipelineState(
            original_prompt  = prompt,
            session_id       = session_id,
            request_id       = request_id or str(uuid.uuid4())[:8],
            pipeline_start_ms= time.perf_counter(),
        )

        if self._graph:
            return self._run_graph(state)
        else:
            return self._run_linear(state)

    # ------------------------------------------------------------------
    # LangGraph Execution
    # ------------------------------------------------------------------

    def _build_graph(self):
        """Compile the LangGraph StateGraph."""

        # LangGraph requires TypedDict for state — wrap PipelineState
        # We use a dict-based state and wrap/unwrap around our dataclass
        from langgraph.graph import StateGraph, END
        from typing import TypedDict as TD

        class GraphState(TD):
            pipeline_state: Any

        graph = StateGraph(GraphState)

        # ── Register nodes ────────────────────────────────────────────
        def _wrap(node_fn):
            def _inner(state: dict) -> dict:
                ps = state["pipeline_state"]
                ps = node_fn(ps)
                return {"pipeline_state": ps}
            _inner.__name__ = node_fn.__name__
            return _inner

        graph.add_node("layer_1_scan",    _wrap(self._nodes.layer_1_scan))
        graph.add_node("layer_2_scan",    _wrap(self._nodes.layer_2_scan))
        graph.add_node("layer_3_scan",    _wrap(self._nodes.layer_3_scan))
        graph.add_node("decide",          _wrap(self._nodes.decide))
        graph.add_node("handle_block",    _wrap(self._nodes.handle_block))
        graph.add_node("handle_sanitize", _wrap(self._nodes.handle_sanitize))
        graph.add_node("handle_allow",    _wrap(self._nodes.handle_allow))
        graph.add_node("run_agent",       _wrap(self._nodes.run_agent))

        # ── Edges ─────────────────────────────────────────────────────
        graph.set_entry_point("layer_1_scan")
        graph.add_edge("layer_1_scan",  "layer_2_scan")
        graph.add_edge("layer_2_scan",  "layer_3_scan")
        graph.add_edge("layer_3_scan",  "decide")

        # Conditional branch after decision
        def _route(state: dict) -> str:
            return PipelineNodes.route_after_decision(state["pipeline_state"])

        graph.add_conditional_edges(
            "decide",
            _route,
            {
                "handle_block":    "handle_block",
                "handle_sanitize": "handle_sanitize",
                "handle_allow":    "handle_allow",
            },
        )

        # All three branches converge at run_agent (except block)
        graph.add_edge("handle_sanitize", "run_agent")
        graph.add_edge("handle_allow",    "run_agent")
        graph.add_edge("handle_block",    END)
        graph.add_edge("run_agent",       END)

        return graph.compile()

    def _run_graph(self, state: PipelineState) -> PipelineState:
        """Execute via compiled LangGraph."""
        result = self._graph.invoke({"pipeline_state": state})
        return result["pipeline_state"]

    # ------------------------------------------------------------------
    # Linear Fallback Execution
    # ------------------------------------------------------------------

    def _run_linear(self, state: PipelineState) -> PipelineState:
        """
        Execute pipeline linearly without LangGraph.
        Identical semantics — just no graph overhead.
        """
        state = self._nodes.layer_1_scan(state)
        state = self._nodes.layer_2_scan(state)
        state = self._nodes.layer_3_scan(state)
        state = self._nodes.decide(state)

        route = PipelineNodes.route_after_decision(state)
        if route == "handle_block":
            state = self._nodes.handle_block(state)
        elif route == "handle_sanitize":
            state = self._nodes.handle_sanitize(state)
            state = self._nodes.run_agent(state)
        else:
            state = self._nodes.handle_allow(state)
            state = self._nodes.run_agent(state)

        return state