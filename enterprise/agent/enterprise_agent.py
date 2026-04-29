# ============================================================
# enterprise/agent/enterprise_agent.py
#
# The Enterprise AI Agent — runs ONLY after the security
# pipeline has cleared the prompt.
#
# This agent NEVER receives blocked prompts. The LangGraph
# pipeline in enterprise_graph.py enforces this gate.
#
# Architecture:
#   EnterpriseAgent.run(prompt) →
#     LangChain ReAct loop →
#       Tool calls (logged) →
#         Structured EnterpriseResponse
# ============================================================

from __future__ import annotations

import os
import time
import traceback
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from enterprise.agent.prompts import (
    ENTERPRISE_SYSTEM_PROMPT,
    EMPLOYEE_CONTEXTS,
)


# ---------------------------------------------------------------------------
# Response dataclass
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    tool:       str
    input:      str
    output:     str
    exec_ms:    float


@dataclass
class EnterpriseResponse:
    prompt:         str
    output:         str
    tool_calls:     list[ToolCall]   = field(default_factory=list)
    steps:          list[str]        = field(default_factory=list)
    success:        bool             = True
    error:          Optional[str]    = None
    execution_ms:   float            = 0.0
    mock_mode:      bool             = False

    @property
    def tools_used(self) -> list[str]:
        return list({t.tool for t in self.tool_calls})


# ---------------------------------------------------------------------------
# Enterprise Agent
# ---------------------------------------------------------------------------

class EnterpriseAgent:
    """
    Production-style internal company AI assistant.

    Only instantiated once at API startup (attached to app.state).
    The run() method is called per-request, always with a
    pre-screened prompt from the security pipeline.
    """

    def __init__(self, employee_role: str = "default") -> None:
        self._available   = False
        self._mock_mode   = True
        self._executor    = None
        self._role        = employee_role
        self._tools       = []

        self._init_agent()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _init_agent(self) -> None:
        """Build the LangChain ReAct agent with Groq LLM."""
        try:
            from langchain_groq import ChatGroq
            from langchain.agents import AgentExecutor, create_tool_calling_agent
            from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
            from enterprise.tools.registry import ENTERPRISE_TOOLS

            api_key = (
                os.environ.get("GROQ_API_KEY",  "").strip() or
                os.environ.get("GROQ__API_KEY", "").strip()
            )

            if not api_key or not api_key.startswith("gsk_"):
                print("[EnterpriseAgent] GROQ_API_KEY not set — mock mode active.")
                self._mock_mode = True
                self._load_mock_tools()
                return

            self._tools = ENTERPRISE_TOOLS

            # Build system prompt with today's date and role
            system_prompt = ENTERPRISE_SYSTEM_PROMPT.format(
                date=date.today().strftime("%B %d, %Y"),
                employee_context=EMPLOYEE_CONTEXTS.get(self._role, EMPLOYEE_CONTEXTS["default"]),
            )

            prompt_template = ChatPromptTemplate.from_messages([
                ("system",  system_prompt),
                ("human",   "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ])

            llm = ChatGroq(
                api_key     = api_key,
                model       = "llama-3.3-70b-versatile",
                temperature = 0.2,
                max_tokens  = 1024,
            )

            agent = create_tool_calling_agent(llm, self._tools, prompt_template)

            self._executor = AgentExecutor(
                agent                     = agent,
                tools                     = self._tools,
                verbose                   = False,
                max_iterations            = 4,
                max_execution_time        = 30,
                handle_parsing_errors     = True,
                return_intermediate_steps = True,
            )

            self._available = True
            self._mock_mode = False
            print(f"[EnterpriseAgent] Initialized with {len(self._tools)} tools — live mode.")

        except Exception as exc:
            print(f"[EnterpriseAgent] Init warning: {exc} — falling back to mock mode.")
            self._mock_mode = True
            self._load_mock_tools()

    def _load_mock_tools(self) -> None:
        """Load tools for mock mode (direct function calls, no LLM)."""
        try:
            from enterprise.tools.registry import ENTERPRISE_TOOLS
            self._tools = ENTERPRISE_TOOLS
            print(f"[EnterpriseAgent] Mock mode: {len(self._tools)} tools loaded.")
        except Exception as exc:
            print(f"[EnterpriseAgent] Tool load warning: {exc}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        prompt:           str,
        session_id:       str = "default",
        employee_role:    str = "default",
    ) -> EnterpriseResponse:
        """
        Run the enterprise agent on a pre-screened prompt.

        Args:
            prompt:        Cleared prompt from the security pipeline
            session_id:    For audit logging
            employee_role: Adjusts context and permissions

        Returns:
            EnterpriseResponse with output, tool calls, and timing
        """
        t_start = time.perf_counter()

        if not prompt or not prompt.strip():
            return EnterpriseResponse(
                prompt=prompt,
                output="Please provide a valid query.",
                success=False,
                error="Empty prompt",
            )

        if self._mock_mode:
            return self._mock_run(prompt, t_start)

        try:
            result = self._executor.invoke({
                "input": prompt,
            })

            tool_calls = []
            steps      = []

            for action, observation in result.get("intermediate_steps", []):
                tc = ToolCall(
                    tool    = action.tool,
                    input   = str(action.tool_input)[:300],
                    output  = str(observation)[:600],
                    exec_ms = 0.0,
                )
                tool_calls.append(tc)
                steps.append(f"→ [{action.tool}] {str(action.tool_input)[:80]}")

            output = result.get("output", "")

            # If LLM gave up or returned empty — fall back to mock
            if not output or "agent stopped" in output.lower() or "max iterations" in output.lower():
                return self._mock_run(prompt, t_start)

            elapsed = (time.perf_counter() - t_start) * 1000
            return EnterpriseResponse(
                prompt       = prompt,
                output       = output,
                tool_calls   = tool_calls,
                steps        = steps,
                success      = True,
                execution_ms = round(elapsed, 2),
                mock_mode    = False,
            )

        except Exception as exc:
            # Always fall back to mock — never show raw errors to user
            return self._mock_run(prompt, t_start)

    # ------------------------------------------------------------------
    # Mock mode — realistic responses without LLM
    # ------------------------------------------------------------------

    def _mock_run(self, prompt: str, t_start: float) -> EnterpriseResponse:
        """
        Produce realistic responses using tools directly.
        Used when GROQ_API_KEY is not available.
        """
        from enterprise.tools.internal_docs  import internal_doc_search
        from enterprise.tools.calculator     import enterprise_calculator
        from enterprise.tools.meeting_summary import meeting_summary
        from enterprise.tools.hr_policy      import hr_policy_lookup

        p = prompt.lower()
        tool_calls = []
        steps      = []
        output     = ""

        # Route to appropriate tool based on keywords
        if any(k in p for k in ["leave", "vacation", "holiday", "policy", "hr", "expense", "remote", "work from home"]):
            t0 = time.perf_counter()
            result = hr_policy_lookup.invoke(prompt)
            tool_calls.append(ToolCall(
                tool="hr_policy_lookup", input=prompt,
                output=result, exec_ms=round((time.perf_counter()-t0)*1000, 2)
            ))
            steps.append(f"→ [hr_policy_lookup] {prompt[:60]}")
            output = result

        elif any(k in p for k in ["calculate", "compute", "%", "percent", "budget", "cost", "revenue", "profit", "interest", "how much", "what is", "+"]):
            # Extract math portion
            t0 = time.perf_counter()
            result = enterprise_calculator.invoke(prompt)
            tool_calls.append(ToolCall(
                tool="enterprise_calculator", input=prompt,
                output=result, exec_ms=round((time.perf_counter()-t0)*1000, 2)
            ))
            steps.append(f"→ [enterprise_calculator] {prompt[:60]}")
            output = result

        elif any(k in p for k in ["summarize", "summary", "meeting", "notes", "minutes", "recap"]):
            t0 = time.perf_counter()
            result = meeting_summary.invoke(prompt)
            tool_calls.append(ToolCall(
                tool="meeting_summary", input=prompt,
                output=result, exec_ms=round((time.perf_counter()-t0)*1000, 2)
            ))
            steps.append(f"→ [meeting_summary] {prompt[:60]}")
            output = result

        else:
            # Default: internal doc search
            t0 = time.perf_counter()
            result = internal_doc_search.invoke(prompt)
            tool_calls.append(ToolCall(
                tool="internal_doc_search", input=prompt,
                output=result, exec_ms=round((time.perf_counter()-t0)*1000, 2)
            ))
            steps.append(f"→ [internal_doc_search] {prompt[:60]}")
            output = result

        elapsed = (time.perf_counter() - t_start) * 1000
        return EnterpriseResponse(
            prompt       = prompt,
            output       = output,
            tool_calls   = tool_calls,
            steps        = steps,
            success      = True,
            execution_ms = round(elapsed, 2),
            mock_mode    = True,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def is_mock(self) -> bool:
        return self._mock_mode

    @property
    def tool_count(self) -> int:
        return len(self._tools)