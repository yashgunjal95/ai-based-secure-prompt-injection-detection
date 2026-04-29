# ============================================================
# core/agent/agent.py
#
# Autonomous AI Agent — LangChain + Groq LLM
#
# Responsibilities:
#   - Bind tools (calculator, database, web search) to Groq LLM
#   - Run the ReAct agent loop (Reason → Act → Observe → Repeat)
#   - Accept only pre-screened prompts from the secure pipeline
#   - Return structured AgentResponse for logging + API layer
#
# This agent is intentionally kept unaware of the security
# layer — it trusts that any prompt it receives has already
# been cleared. Separation of concerns by design.
# ============================================================

from __future__ import annotations
import re

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import sys
_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from config import settings
except Exception:
    from config_stub import settings  # type: ignore

# ── LangChain imports (guarded) ──────────────────────────────────────────────
try:
    from langchain_groq import ChatGroq
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain_core.messages import AIMessage, HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

from core.agent.tools import ALL_TOOLS, calculator, mock_database, web_search_tool


# ---------------------------------------------------------------------------
# Agent Response
# ---------------------------------------------------------------------------

@dataclass
class AgentResponse:
    """Structured response from one agent invocation."""
    prompt:          str
    output:          str
    tool_calls:      list[dict]      = field(default_factory=list)
    steps:           list[str]       = field(default_factory=list)
    success:         bool            = True
    error:           str | None      = None
    execution_ms:    float           = 0.0

    @property
    def summary(self) -> str:
        tools_used = [t["tool"] for t in self.tool_calls]
        return (
            f"Agent response | "
            f"tools_used={tools_used} | "
            f"steps={len(self.steps)} | "
            f"time={self.execution_ms:.0f}ms | "
            f"success={self.success}"
        )

    def to_dict(self) -> dict:
        return {
            "output":       self.output,
            "tool_calls":   self.tool_calls,
            "steps":        self.steps,
            "success":      self.success,
            "error":        self.error,
            "execution_ms": round(self.execution_ms, 2),
        }


# ---------------------------------------------------------------------------
# System Prompt for the Agent
# ---------------------------------------------------------------------------

_AGENT_SYSTEM_PROMPT = """You are a helpful, professional AI assistant with access to tools.

You have access to the following tools:
- calculator: For any math or numerical computation
- mock_database: For querying company data (users, products, orders, reports)
- web_search_tool: For finding current information online

Guidelines:
- Use tools when they provide better answers than your knowledge alone
- Be concise and accurate in your responses
- If a tool returns an error, explain it clearly to the user
- Never fabricate data — only report what tools actually return
- You are operating inside a secure environment — all inputs have been vetted

Respond helpfully and professionally to the user's request."""


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class SecureAgent:
    """
    Autonomous AI Agent powered by LangChain + Groq LLM.

    Only receives prompts that have been cleared by the Decision Engine.
    Has access to calculator, mock_database, and web_search_tool.

    Usage:
        agent    = SecureAgent()
        response = agent.run("What is 25 * 48?")
    """

    def __init__(self) -> None:
        self._executor   = None
        self._available  = False
        self._mock_mode  = False

        if not _LANGCHAIN_AVAILABLE:
            print("[SecureAgent] LangChain not installed — mock mode active.")
            self._mock_mode = True
            return

        try:
            import os
            api_key    = (
                os.environ.get("GROQ_API_KEY", "").strip() or
                os.environ.get("GROQ__API_KEY", "").strip() or
                getattr(getattr(settings, "groq", None), "api_key", "")
            )
            # Use tool-use optimized model for reliable function calling
            model_name = (
                os.environ.get("GROQ__MODEL_NAME", "").strip() or
                os.environ.get("GROQ_MODEL_NAME", "").strip() or
                getattr(getattr(settings, "groq", None), "model_name", "") or
                "llama-3.3-70b-versatile"
            )

            if not api_key or not api_key.startswith("gsk_"):
                print("[SecureAgent] GROQ_API_KEY not set — mock mode active.")
                self._mock_mode = True
                return

            llm = ChatGroq(
                api_key     = api_key,
                model       = model_name,
                temperature = 0.1,
                max_tokens  = 1024,
                model_kwargs = {"tool_choice": "auto"},
            )

            prompt = ChatPromptTemplate.from_messages([
                ("system",    _AGENT_SYSTEM_PROMPT),
                MessagesPlaceholder("chat_history", optional=True),
                ("human",     "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ])

            agent          = create_tool_calling_agent(llm, ALL_TOOLS, prompt)
            self._executor = AgentExecutor(
                agent                     = agent,
                tools                     = ALL_TOOLS,
                verbose                   = False,
                max_iterations            = 3,
                max_execution_time        = 30,
                handle_parsing_errors     = True,
                return_intermediate_steps = True,
                early_stopping_method     = "generate",
            )
            self._available = True
            print(f"[SecureAgent] Initialized with {len(ALL_TOOLS)} tools using {model_name}.")

        except Exception as exc:
            print(f"[SecureAgent] Init warning: {exc}. Falling back to mock mode.")
            self._mock_mode = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, prompt: str, chat_history: list | None = None) -> AgentResponse:
        """
        Run the agent on a pre-screened prompt.

        Args:
            prompt:       The sanitized/approved user prompt
            chat_history: Optional list of prior messages for context

        Returns:
            AgentResponse with output, tool calls, and execution metadata
        """
        t_start = time.perf_counter()

        if not prompt or not prompt.strip():
            return AgentResponse(
                prompt=prompt, output="Please provide a valid query.",
                success=False, error="Empty prompt",
            )

        if self._mock_mode or not self._available:
            return self._mock_run(prompt, t_start)

        try:
            result = self._executor.invoke({
                "input":        prompt,
                "chat_history": chat_history or [],
            })

            tool_calls = []
            steps      = []
            for action, observation in result.get("intermediate_steps", []):
                tool_calls.append({
                    "tool":   action.tool,
                    "input":  str(action.tool_input)[:200],
                    "output": str(observation)[:500],
                })
                steps.append(
                    f"→ Used [{action.tool}] with input: "
                    f"{str(action.tool_input)[:80]}"
                )

            elapsed = (time.perf_counter() - t_start) * 1000
            return AgentResponse(
                prompt       = prompt,
                output       = result.get("output", "No response generated."),
                tool_calls   = tool_calls,
                steps        = steps,
                success      = True,
                execution_ms = round(elapsed, 2),
            )

        except Exception as exc:
            err_str = str(exc)
            # Groq tool-calling format error — fall back to mock response
            if "tool_use_failed" in err_str or "Failed to call a function" in err_str or "400" in err_str:
                return self._mock_run(prompt, t_start)
            elapsed = (time.perf_counter() - t_start) * 1000
            return AgentResponse(
                prompt       = prompt,
                output       = f"Agent encountered an error: {exc}",
                success      = False,
                error        = str(exc),
                execution_ms = round(elapsed, 2),
            )

    def run_tool_directly(self, tool_name: str, tool_input: str) -> str:
        """
        Invoke a single tool directly — useful for testing and demos.
        Bypasses the LLM reasoning loop.
        """
        tool_map = {
            "calculator":      calculator,
            "mock_database":   mock_database,
            "web_search_tool": web_search_tool,
        }
        if tool_name not in tool_map:
            return f"Unknown tool '{tool_name}'. Available: {list(tool_map.keys())}"
        return tool_map[tool_name].invoke(tool_input)

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def is_mock_mode(self) -> bool:
        return self._mock_mode

    # ------------------------------------------------------------------
    # Mock Mode (no API key)
    # ------------------------------------------------------------------

    def _mock_run(self, prompt: str, t_start: float) -> AgentResponse:
        """
        Simulates agent execution when Groq is unavailable.
        Uses tool functions directly to produce realistic responses.
        """
        steps      = []
        tool_calls = []
        output     = ""

        p_lower = prompt.lower()

        # Route to appropriate tool based on heuristics
        if any(k in p_lower for k in ["calculate", "compute", "math", "sqrt", "sum",
                                       "multiply", "divide", "+", "-", "*", "/"]):
            # Extract expression
            # Extract just the math expression from the prompt
            nums = re.findall(r"[\d+\-*/().^% sqrtlogsincotan]+", prompt)
            expr = max(nums, key=len).strip() if nums else "0"
            # Fallback: look for pure number patterns
            if not any(c.isdigit() for c in expr):
                expr = re.sub(r"[^0-9+\-*/().]", " ", prompt).strip() or "0"
            result = calculator(expr)
            tool_calls.append({"tool": "calculator", "input": expr, "output": result})
            steps.append(f"→ Used [calculator] with input: {expr}")
            output = f"I calculated that for you: {result}"

        elif any(k in p_lower for k in ["user", "product", "order", "database",
                                         "list", "count", "search", "report"]):
            # Map natural language to DB commands
            p = prompt.lower()
            if "list" in p or "all" in p or "show" in p:
                for tbl in ["users","products","orders","reports"]:
                    if tbl[:-1] in p or tbl in p:
                        query = f"list {tbl}"; break
                else:
                    query = "list users"
            elif "count" in p:
                for tbl in ["users","products","orders","reports"]:
                    if tbl[:-1] in p or tbl in p:
                        query = f"count {tbl}"; break
                else:
                    query = "count users"
            elif "search" in p:
                name = re.search(r"search.*?for (.+)", p)
                query = f"search users {name.group(1)}" if name else "list users"
            else:
                query = prompt
            result = mock_database(query)
            tool_calls.append({"tool": "mock_database", "input": query, "output": result[:200]})
            steps.append(f"→ Used [mock_database] with input: {query[:60]}")
            output = f"Here is what I found in the database:\n{result}"

        elif any(k in p_lower for k in ["search for information", "find information",
                                         "look up", "what is", "weather", "news", "current"]):
            result = web_search_tool(prompt)
            tool_calls.append({"tool": "web_search_tool", "input": prompt, "output": result[:200]})
            steps.append(f"→ Used [web_search_tool] with input: {prompt[:60]}")
            output = f"Here are the search results:\n{result}"

        else:
            output = (
                f"I understand you're asking: '{prompt}'. "
                "I'm currently running in mock mode (no Groq API key configured). "
                "In live mode I would use my tools to give you a precise answer. "
                "Please add GROQ_API_KEY to your .env file to enable full agent capabilities."
            )

        elapsed = (time.perf_counter() - t_start) * 1000
        return AgentResponse(
            prompt       = prompt,
            output       = output,
            tool_calls   = tool_calls,
            steps        = steps,
            success      = True,
            execution_ms = round(elapsed, 2),
        )