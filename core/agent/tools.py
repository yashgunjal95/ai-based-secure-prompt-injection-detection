# ============================================================
# core/agent/tools.py
#
# Tool definitions for the Autonomous AI Agent.
#
# Tools available to the agent:
#   1. calculator       — safe math expression evaluator
#   2. mock_database    — simulated sensitive user database
#   3. web_search_tool  — simulated web search (indirect injection surface)
#
# Each tool is implemented as a LangChain @tool decorated function.
# The mock_database is intentionally "sensitive" — it represents
# the high-value asset that prompt injection attacks target.
# ============================================================

from __future__ import annotations

import ast
import json
import math
import operator
import re
from datetime import datetime
from typing import Any

try:
    from langchain_core.tools import tool
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    # Fallback decorator so the module still imports without langchain
    def tool(func):  # type: ignore
        func.name = func.__name__
        func.description = func.__doc__ or ""
        return func
    _LANGCHAIN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Tool 1: Safe Calculator
# ---------------------------------------------------------------------------

# Whitelist of safe AST node types for math evaluation
_SAFE_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod,
    ast.FloorDiv, ast.USub, ast.UAdd, ast.Call, ast.Name, ast.Load,
)

_SAFE_NAMES = {
    "abs": abs, "round": round, "min": min, "max": max,
    "sqrt": math.sqrt, "pow": math.pow, "log": math.log,
    "log10": math.log10, "sin": math.sin, "cos": math.cos,
    "tan": math.tan, "pi": math.pi, "e": math.e, "ceil": math.ceil,
    "floor": math.floor, "factorial": math.factorial,
}


def _safe_eval(expression: str) -> float:
    """Evaluate a math expression safely using AST whitelisting."""
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Invalid expression syntax: {exc}") from exc

    for node in ast.walk(tree):
        if not isinstance(node, _SAFE_NODES):
            raise ValueError(
                f"Unsafe operation in expression: {type(node).__name__}"
            )

    code = compile(tree, "<calculator>", "eval")
    return eval(code, {"__builtins__": {}}, _SAFE_NAMES)  # noqa: S307


@tool
def calculator(expression: str) -> str:
    """
    Evaluate a mathematical expression and return the result.
    Supports: +, -, *, /, **, %, sqrt, log, sin, cos, tan, pi, e, factorial.
    Example inputs: '2 + 2', 'sqrt(144)', 'sin(pi/2)', '10 * (3 + 4)'
    """
    try:
        # Sanitize: remove any non-math characters
        clean = re.sub(r"[^0-9+\-*/().,%^a-zA-Z_ ]", "", expression)
        if not clean.strip():
            return "Error: Empty expression after sanitization."

        result = _safe_eval(clean)

        # Format nicely
        if isinstance(result, float) and result.is_integer():
            return f"Result: {int(result)}"
        return f"Result: {round(result, 10)}"

    except ZeroDivisionError:
        return "Error: Division by zero."
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error evaluating expression: {exc}"


# ---------------------------------------------------------------------------
# Tool 2: Mock Sensitive Database
# ---------------------------------------------------------------------------

# This simulates a real company database with sensitive records.
# In a real deployment this would be a SQL/NoSQL query layer.
# The sensitivity is intentional — this is what attackers want to exfiltrate.

_MOCK_DB: dict[str, Any] = {
    "users": [
        {"id": "U001", "name": "Alice Johnson", "role": "admin",
         "email": "alice@company.com",  "department": "Engineering"},
        {"id": "U002", "name": "Bob Smith",     "role": "developer",
         "email": "bob@company.com",    "department": "Engineering"},
        {"id": "U003", "name": "Carol White",   "role": "analyst",
         "email": "carol@company.com",  "department": "Finance"},
        {"id": "U004", "name": "David Brown",   "role": "manager",
         "email": "david@company.com",  "department": "Operations"},
    ],
    "products": [
        {"id": "P001", "name": "SecureVault Pro",   "price": 299.99, "stock": 42},
        {"id": "P002", "name": "DataShield Basic",  "price":  99.99, "stock": 120},
        {"id": "P003", "name": "CipherGuard Elite", "price": 499.99, "stock": 15},
    ],
    "orders": [
        {"id": "O001", "user_id": "U001", "product_id": "P001",
         "amount": 299.99,  "status": "completed", "date": "2025-01-15"},
        {"id": "O002", "user_id": "U002", "product_id": "P002",
         "amount":  99.99,  "status": "pending",   "date": "2025-01-20"},
        {"id": "O003", "user_id": "U003", "product_id": "P003",
         "amount": 499.99,  "status": "completed", "date": "2025-01-22"},
    ],
    "reports": [
        {"id": "R001", "title": "Q4 Revenue Summary",
         "summary": "Total Q4 revenue: $2.4M, up 18% YoY."},
        {"id": "R002", "title": "Security Audit 2024",
         "summary": "No critical vulnerabilities found. 3 medium issues resolved."},
    ],
}


@tool
def mock_database(query: str) -> str:
    """
    Query the company database for information.
    Supported queries:
      - 'list users'           — show all users
      - 'list products'        — show all products
      - 'list orders'          — show all orders
      - 'list reports'         — show available reports
      - 'get user <id>'        — get a specific user by ID (e.g. 'get user U001')
      - 'get product <id>'     — get a specific product by ID
      - 'get order <id>'       — get a specific order by ID
      - 'count <table>'        — count records in a table
      - 'search users <name>'  — search users by name
    """
    q = query.strip().lower()

    try:
        # LIST commands
        if q.startswith("list "):
            table = q[5:].strip()
            if table not in _MOCK_DB:
                return f"Unknown table '{table}'. Available: {list(_MOCK_DB.keys())}"
            records = _MOCK_DB[table]
            return json.dumps(records, indent=2)

        # GET commands
        elif q.startswith("get "):
            parts = q[4:].split()
            if len(parts) < 2:
                return "Usage: get <table_singular> <id>"
            entity, record_id = parts[0], parts[1].upper()
            # Map singular to plural
            table_map = {
                "user": "users", "product": "products",
                "order": "orders", "report": "reports"
            }
            table = table_map.get(entity, entity + "s")
            if table not in _MOCK_DB:
                return f"Unknown entity '{entity}'."
            found = [r for r in _MOCK_DB[table] if r.get("id") == record_id]
            if not found:
                return f"No {entity} found with id '{record_id}'."
            return json.dumps(found[0], indent=2)

        # COUNT commands
        elif q.startswith("count "):
            table = q[6:].strip()
            if table not in _MOCK_DB:
                return f"Unknown table '{table}'."
            return f"Count of '{table}': {len(_MOCK_DB[table])} records."

        # SEARCH commands
        elif q.startswith("search users "):
            name_query = q[13:].strip()
            matches = [
                u for u in _MOCK_DB["users"]
                if name_query in u["name"].lower()
            ]
            if not matches:
                return f"No users found matching '{name_query}'."
            return json.dumps(matches, indent=2)

        else:
            return (
                "Unrecognized query format. "
                "Try: 'list users', 'get user U001', 'count products', "
                "'search users alice'"
            )

    except Exception as exc:
        return f"Database error: {exc}"


# ---------------------------------------------------------------------------
# Tool 3: Simulated Web Search
# ---------------------------------------------------------------------------

# Pre-canned search results — simulates a real search API.
# This surface is where INDIRECT prompt injection would occur in a real system
# (malicious content embedded in search results that re-prompts the agent).

_SEARCH_RESULTS: dict[str, list[dict]] = {
    "python":       [{"title": "Python.org",                "snippet": "Python is a high-level programming language."},
                     {"title": "Python Tutorial — W3Schools","snippet": "Learn Python with examples and exercises."}],
    "langchain":    [{"title": "LangChain Docs",             "snippet": "LangChain is a framework for developing LLM applications."},
                     {"title": "LangChain GitHub",           "snippet": "Open-source library with 70k+ stars on GitHub."}],
    "security":     [{"title": "OWASP Top 10",               "snippet": "OWASP identifies the top 10 web application security risks."},
                     {"title": "NIST Cybersecurity Framework","snippet": "Framework for improving critical infrastructure security."}],
    "ai":           [{"title": "What is AI? — IBM",          "snippet": "Artificial intelligence refers to simulation of human intelligence."},
                     {"title": "OpenAI Research",            "snippet": "OpenAI conducts research on AI safety and capabilities."}],
    "weather":      [{"title": "Weather.com",                "snippet": "Current weather: 22°C, partly cloudy. Wind: 12 km/h NW."},
                     {"title": "AccuWeather",                "snippet": "7-day forecast shows mild temperatures with some rain Thursday."}],
    "machine learning": [{"title": "ML Crash Course — Google","snippet": "Free course on fundamentals of machine learning."},
                         {"title": "Scikit-learn Docs",       "snippet": "Python ML library with classification, regression tools."}],
}

_DEFAULT_RESULTS = [
    {"title": "Wikipedia",        "snippet": "Wikipedia is a free online encyclopedia."},
    {"title": "Search Engine Result", "snippet": "Relevant information about your query found online."},
]


@tool
def web_search_tool(query: str) -> str:
    """
    Search the web for current information on a topic.
    Returns the top search results with titles and snippets.
    Example: web_search_tool('Python programming tutorials')
    """
    if not query or not query.strip():
        return "Error: Empty search query."

    q_lower = query.lower()

    # Find best matching pre-canned results
    results = _DEFAULT_RESULTS
    for keyword, res in _SEARCH_RESULTS.items():
        if keyword in q_lower:
            results = res
            break

    output = [f"Search results for: '{query}'\n"]
    for i, r in enumerate(results, 1):
        output.append(f"{i}. {r['title']}")
        output.append(f"   {r['snippet']}")
    output.append(f"\n[{len(results)} results returned | {datetime.now().strftime('%Y-%m-%d')}]")
    return "\n".join(output)


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------

ALL_TOOLS = [calculator, mock_database, web_search_tool]

TOOL_DESCRIPTIONS = {
    "calculator":      "Evaluates mathematical expressions safely.",
    "mock_database":   "Queries the company database for users, products, orders.",
    "web_search_tool": "Searches the web for current information.",
}