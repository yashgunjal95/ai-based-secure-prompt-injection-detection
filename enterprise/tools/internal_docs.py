# ============================================================
# enterprise/tools/internal_docs.py
#
# Tool: internal_doc_search
#
# Searches AcmeCorp's internal knowledge base.
# Uses simple keyword + TF-IDF-style scoring (no external deps).
# Returns top 2 matching documents with source attribution.
# ============================================================

from __future__ import annotations
import re
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


def _score_document(doc: dict, query: str) -> float:
    """Score a document against a query using keyword overlap."""
    query_words = set(re.findall(r"\w+", query.lower()))
    score = 0.0

    # Check tags (high weight)
    for tag in doc.get("tags", []):
        tag_words = set(re.findall(r"\w+", tag.lower()))
        overlap = query_words & tag_words
        score += len(overlap) * 2.0

    # Check title (medium weight)
    title_words = set(re.findall(r"\w+", doc.get("title", "").lower()))
    score += len(query_words & title_words) * 1.5

    # Check content (low weight)
    content_words = set(re.findall(r"\w+", doc.get("content", "").lower()))
    score += len(query_words & content_words) * 0.5

    return score


@tool
def internal_doc_search(query: str) -> str:
    """
    Search AcmeCorp's internal company documents, wikis, and project documentation.

    Use this tool when an employee asks about:
    - Company policies (expense, travel, remote work, performance)
    - Project information and roadmaps
    - Onboarding and HR processes
    - IT guidelines and security policies
    - Any internal AcmeCorp information

    Args:
        query: The search query describing what information is needed

    Returns:
        Relevant document excerpts with source attribution
    """
    from enterprise.data.company_docs import COMPANY_DOCS

    if not query or not query.strip():
        return "Please provide a search query."

    # Score all documents
    scored = [
        (doc, _score_document(doc, query))
        for doc in COMPANY_DOCS
    ]

    # Sort by score, take top 2
    scored.sort(key=lambda x: x[1], reverse=True)
    top_docs = [(doc, score) for doc, score in scored if score > 0][:2]

    if not top_docs:
        return (
            "No matching documents found in the internal knowledge base for your query.\n"
            "Please try different keywords, or contact the relevant department directly:\n"
            "  • HR queries: hr@acmecorp.com\n"
            "  • IT queries: it-helpdesk@acmecorp.com\n"
            "  • Finance queries: finance@acmecorp.com"
        )

    results = []
    for doc, score in top_docs:
        results.append(
            f"📄 **{doc['title']}** [{doc['id']}] — {doc['department']}\n"
            f"{doc['content']}"
        )

    return "\n\n---\n\n".join(results) + \
           "\n\n*Source: AcmeCorp Internal Knowledge Base*"