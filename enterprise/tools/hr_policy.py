# ============================================================
# enterprise/tools/hr_policy.py
#
# Tool: hr_policy_lookup
#
# Looks up AcmeCorp HR policies by topic.
# Returns the relevant policy section with version info.
# ============================================================

from __future__ import annotations
try:
    from langchain_core.tools import tool
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    def tool(func):  # type: ignore
        func.name = func.__name__
        func.description = func.__doc__ or ""
        func.invoke = lambda x, **kw: func(x)
        return func
    _LANGCHAIN_AVAILABLE = False


def _find_best_policy(query: str) -> tuple[str | None, dict | None]:
    """Find the best matching policy key for a query."""
    from enterprise.data.hr_policies import HR_POLICIES, POLICY_KEYWORDS

    q = query.lower()
    best_key   = None
    best_score = 0

    for policy_key, keywords in POLICY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in q)
        if score > best_score:
            best_score = score
            best_key   = policy_key

    if best_key and best_score > 0:
        return best_key, HR_POLICIES.get(best_key)

    # Fallback: check if any policy key itself appears in the query
    for key in HR_POLICIES:
        if key.replace("_", " ") in q or key in q:
            return key, HR_POLICIES[key]

    return None, None


@tool
def hr_policy_lookup(query: str) -> str:
    """
    Look up AcmeCorp HR policies and employee guidelines.

    Use this tool for questions about:
    - Leave and vacation policies (annual, sick, maternity, paternity)
    - Expense reimbursement limits and process
    - Remote work and hybrid work rules
    - Performance review process and ratings
    - Code of conduct and ethics
    - Recruitment and hiring policies
    - IT security policies
    - Employee benefits (insurance, PF, wellness)

    Args:
        query: The HR topic or policy you want to look up

    Returns:
        The relevant HR policy details with version information
    """
    if not query or not query.strip():
        return "Please specify an HR policy topic to look up."

    policy_key, policy = _find_best_policy(query)

    if not policy:
        return (
            "I couldn't find a specific policy matching your query.\n\n"
            "Available policy topics:\n"
            "  • Leave & Time-Off\n"
            "  • Expense Reimbursement\n"
            "  • Remote / Hybrid Work\n"
            "  • Performance Reviews\n"
            "  • Code of Conduct\n"
            "  • Hiring & Recruitment\n"
            "  • IT Security\n"
            "  • Employee Benefits\n\n"
            "For specific queries, contact: hr@acmecorp.com"
        )

    return (
        f"## {policy['title']}\n"
        f"*{policy['version']}*\n\n"
        f"{policy['content']}\n\n"
        f"---\n"
        f"*Source: AcmeCorp HR Policy Portal | "
        f"For clarifications: hr@acmecorp.com*"
    )