# ============================================================
# enterprise/tools/registry.py
#
# Central registry for all enterprise agent tools.
#
# Import ENTERPRISE_TOOLS and pass to LangChain AgentExecutor.
# All tools are explicitly listed — no dynamic loading.
# ============================================================

from enterprise.tools.internal_docs    import internal_doc_search
from enterprise.tools.calculator       import enterprise_calculator
from enterprise.tools.meeting_summary  import meeting_summary
from enterprise.tools.hr_policy        import hr_policy_lookup

# The complete tool belt for the Enterprise Agent
ENTERPRISE_TOOLS = [
    internal_doc_search,
    enterprise_calculator,
    meeting_summary,
    hr_policy_lookup,
]

# Tool descriptions for logging and UI display
TOOL_DESCRIPTIONS = {
    "internal_doc_search":  "Search internal company documents and wikis",
    "enterprise_calculator": "Business and financial calculations",
    "meeting_summary":       "Summarize and structure meeting notes",
    "hr_policy_lookup":      "Look up HR policies and employee guidelines",
}

TOOL_ICONS = {
    "internal_doc_search":   "📄",
    "enterprise_calculator": "🧮",
    "meeting_summary":       "📝",
    "hr_policy_lookup":      "📋",
}

__all__ = [
    "ENTERPRISE_TOOLS",
    "TOOL_DESCRIPTIONS",
    "TOOL_ICONS",
    "internal_doc_search",
    "enterprise_calculator",
    "meeting_summary",
    "hr_policy_lookup",
]