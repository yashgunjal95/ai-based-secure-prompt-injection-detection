# ============================================================
# enterprise/agent/enterprise_graph.py
#
# LangGraph orchestration for the Enterprise AI Assistant.
#
# Flow:
#   input → security_gate → [block|run_agent] → output
#
# The security_gate node checks the pipeline routing decision.
# If BLOCK → returns security warning immediately.
# If ALLOW or SANITIZE → passes to enterprise agent.
#
# The existing SecurePipeline is called first (in the API route),
# and its state is passed into this graph as context.
# ============================================================

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from enterprise.agent.enterprise_agent import EnterpriseAgent, EnterpriseResponse


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@dataclass
class EnterpriseState:
    """
    Carries all data through the enterprise LangGraph nodes.
    Initialized from the security pipeline's output state.
    """
    # Input
    original_prompt:    str  = ""
    session_id:         str  = "default"
    employee_role:      str  = "default"

    # From security pipeline (populated before graph runs)
    security_routing:   str  = "allow"      # allow | sanitize | block
    security_score:     float = 0.0
    security_reasons:   list[str] = field(default_factory=list)
    security_overrides: list[str] = field(default_factory=list)
    sanitized_prompt:   Optional[str] = None  # cleaned prompt if sanitized

    # Layer scores (for UI display)
    layer_scores:       dict = field(default_factory=dict)
    rule_matches:       int  = 0
    rule_categories:    list[str] = field(default_factory=list)
    ml_label:           str  = ""
    ml_confidence:      float = 0.0
    llm_verdict:        str  = ""
    llm_attack:         str  = ""

    # Agent output (set by run_agent node)
    agent_output:       str  = ""
    tool_calls:         list = field(default_factory=list)
    steps:              list[str] = field(default_factory=list)
    agent_success:      bool = True
    agent_mock_mode:    bool = False

    # Final
    final_output:       str  = ""
    blocked:            bool = False
    completed:          bool = False
    errors:             list[str] = field(default_factory=list)
    node_timings:       dict = field(default_factory=dict)
    total_ms:           float = 0.0


# ---------------------------------------------------------------------------
# Security Warning Templates
# ---------------------------------------------------------------------------

_BLOCK_MESSAGES = {
    "critical_rule_fired": (
        "🚫 **Access Denied — Security Policy Violation**\n\n"
        "Your request was blocked because it matches a known prompt injection pattern. "
        "This incident has been logged.\n\n"
        "If you believe this is an error, please contact IT Security."
    ),
    "llm_verdict_malicious": (
        "🚫 **Access Denied — Suspicious Request Detected**\n\n"
        "Our AI security system identified this request as a potential attempt to "
        "manipulate the assistant outside its intended use.\n\n"
        "AcmeCorp's AI assistant is for internal business use only. "
        "Please rephrase your request or contact your manager for assistance."
    ),
    "all_layers_agree_block": (
        "🚫 **Access Denied — Multi-Layer Security Block**\n\n"
        "This request was flagged by multiple security layers simultaneously. "
        "It has been logged for review by the security team.\n\n"
        "Aria is AcmeCorp's internal assistant. It cannot be used for "
        "unauthorized purposes."
    ),
    "default": (
        "🚫 **Request Blocked by Security Pipeline**\n\n"
        "Your request did not pass AcmeCorp's AI security checks. "
        "This is logged automatically.\n\n"
        "Please ensure your requests are within the scope of internal business use."
    ),
}


def _build_block_message(reasons: list[str], score: float, overrides: list[str]) -> str:
    """Pick the most relevant block message based on reasons."""
    for reason in reasons:
        if reason in _BLOCK_MESSAGES:
            msg = _BLOCK_MESSAGES[reason]
            break
    else:
        msg = _BLOCK_MESSAGES["default"]

    # Append technical details (for demo transparency)
    detail = (
        f"\n\n---\n"
        f"*Security Score: {score:.3f} | "
        f"Reasons: {', '.join(r.replace('_', ' ') for r in reasons)}*"
    )
    if overrides:
        detail += f"\n*Overrides: {', '.join(o.replace('_', ' ') for o in overrides)}*"

    return msg + detail


# ---------------------------------------------------------------------------
# Graph Nodes
# ---------------------------------------------------------------------------

class EnterpriseNodes:
    """Node functions for the enterprise LangGraph."""

    def __init__(self, agent: "EnterpriseAgent") -> None:
        self._agent = agent

    def security_gate(self, state: EnterpriseState) -> EnterpriseState:
        """
        Gate node — checks security pipeline decision.
        Sets state.blocked = True if routing is 'block'.
        This is the ONLY enforcement point needed — the API
        already ran the full pipeline before this graph starts.
        """
        t = time.perf_counter()

        if state.security_routing == "block":
            state.blocked      = True
            state.final_output = _build_block_message(
                reasons   = state.security_reasons,
                score     = state.security_score,
                overrides = state.security_overrides,
            )
            state.completed = True

        state.node_timings["security_gate"] = (time.perf_counter() - t) * 1000
        return state

    def run_agent(self, state: EnterpriseState) -> EnterpriseState:
        """
        Agent node — runs enterprise agent on the cleared prompt.
        Uses sanitized_prompt if available (sanitize routing),
        otherwise uses original_prompt.
        """
        t = time.perf_counter()

        # Use sanitized prompt if the pipeline cleaned it
        effective_prompt = state.sanitized_prompt or state.original_prompt

        try:
            response: "EnterpriseResponse" = self._agent.run(
                prompt        = effective_prompt,
                session_id    = state.session_id,
                employee_role = state.employee_role,
            )

            state.agent_output   = response.output
            state.tool_calls     = [
                {
                    "tool":    tc.tool,
                    "input":   tc.input,
                    "output":  tc.output,
                    "exec_ms": tc.exec_ms,
                }
                for tc in response.tool_calls
            ]
            state.steps          = response.steps
            state.agent_success  = response.success
            state.agent_mock_mode = response.mock_mode
            state.final_output   = response.output
            state.completed      = True

            if response.error:
                state.errors.append(f"agent_error: {response.error}")

        except Exception as exc:
            state.errors.append(f"agent_node_error: {exc}")
            state.final_output = (
                "I'm sorry, I encountered an unexpected error. "
                "Please try again or contact IT support."
            )
            state.agent_success = False
            state.completed     = True

        state.node_timings["run_agent"] = (time.perf_counter() - t) * 1000
        return state


# ---------------------------------------------------------------------------
# Graph Builder
# ---------------------------------------------------------------------------

def _should_run_agent(state: EnterpriseState) -> str:
    """Routing function — block or run agent."""
    return "blocked" if state.blocked else "run_agent"


class EnterpriseGraph:
    """
    Wraps the LangGraph flow for the enterprise agent.

    Usage:
        graph = EnterpriseGraph(agent)
        state = graph.run(prompt, security_pipeline_state)
    """

    def __init__(self, agent: "EnterpriseAgent") -> None:
        self._nodes = EnterpriseNodes(agent)
        self._graph = self._build_graph()

    def _build_graph(self):
        """Compile the LangGraph state machine."""
        try:
            from langgraph.graph import StateGraph, END

            # Use dict-based state for LangGraph compatibility
            builder = StateGraph(dict)

            builder.add_node("security_gate", self._gate_wrapper)
            builder.add_node("run_agent",     self._agent_wrapper)
            builder.add_node("blocked",       self._blocked_wrapper)

            builder.set_entry_point("security_gate")
            builder.add_conditional_edges(
                "security_gate",
                lambda s: "blocked" if s.get("blocked") else "run_agent",
            )
            builder.add_edge("run_agent", END)
            builder.add_edge("blocked",   END)

            print("[EnterpriseGraph] LangGraph compiled successfully.")
            return builder.compile()

        except Exception as exc:
            print(f"[EnterpriseGraph] LangGraph build warning: {exc} — using sequential fallback.")
            return None

    # ── LangGraph wrapper methods (dict ↔ dataclass) ──────────────────

    def _gate_wrapper(self, state_dict: dict) -> dict:
        state = EnterpriseState(**{
            k: v for k, v in state_dict.items()
            if k in EnterpriseState.__dataclass_fields__
        })
        state = self._nodes.security_gate(state)
        return state.__dict__

    def _agent_wrapper(self, state_dict: dict) -> dict:
        state = EnterpriseState(**{
            k: v for k, v in state_dict.items()
            if k in EnterpriseState.__dataclass_fields__
        })
        state = self._nodes.run_agent(state)
        return state.__dict__

    def _blocked_wrapper(self, state_dict: dict) -> dict:
        # Already handled in security_gate — just pass through
        return state_dict

    # ------------------------------------------------------------------
    # Public run method
    # ------------------------------------------------------------------

    def run(
        self,
        prompt:              str,
        security_routing:    str,
        security_score:      float,
        security_reasons:    list[str],
        security_overrides:  list[str],
        layer_scores:        dict,
        rule_matches:        int       = 0,
        rule_categories:     list[str] = None,
        ml_label:            str       = "",
        ml_confidence:       float     = 0.0,
        llm_verdict:         str       = "",
        llm_attack:          str       = "",
        sanitized_prompt:    str       = None,
        session_id:          str       = "default",
        employee_role:       str       = "default",
    ) -> EnterpriseState:
        """
        Run the enterprise graph.

        Args:
            prompt:           Original user prompt
            security_routing: Output from security pipeline (allow/sanitize/block)
            security_score:   Final risk score from pipeline
            ... (all other fields from pipeline's DecisionRecord)

        Returns:
            EnterpriseState with final_output, tool_calls, and all metadata
        """
        t_start = time.perf_counter()

        initial_state = EnterpriseState(
            original_prompt    = prompt,
            session_id         = session_id,
            employee_role      = employee_role,
            security_routing   = security_routing,
            security_score     = security_score,
            security_reasons   = security_reasons or [],
            security_overrides = security_overrides or [],
            sanitized_prompt   = sanitized_prompt,
            layer_scores       = layer_scores or {},
            rule_matches       = rule_matches,
            rule_categories    = rule_categories or [],
            ml_label           = ml_label,
            ml_confidence      = ml_confidence,
            llm_verdict        = llm_verdict,
            llm_attack         = llm_attack,
        )

        try:
            if self._graph:
                # Run via LangGraph
                result_dict = self._graph.invoke(initial_state.__dict__)
                final_state = EnterpriseState(**{
                    k: v for k, v in result_dict.items()
                    if k in EnterpriseState.__dataclass_fields__
                })
            else:
                # Sequential fallback
                final_state = self._nodes.security_gate(initial_state)
                if not final_state.blocked:
                    final_state = self._nodes.run_agent(final_state)

        except Exception as exc:
            initial_state.errors.append(f"graph_error: {exc}")
            initial_state.final_output = "System error — please try again."
            initial_state.completed    = True
            final_state = initial_state

        final_state.total_ms = (time.perf_counter() - t_start) * 1000
        return final_state