# ============================================================
# enterprise/tools/meeting_summary.py
#
# Tool: meeting_summary
#
# Structures and summarizes meeting notes into a clear format.
# Works in two modes:
#   1. If notes are provided — extracts decisions, action items
#   2. If only a topic is provided — generates a template
# ============================================================

from __future__ import annotations
import re
from datetime import date
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


def _extract_action_items(text: str) -> list[str]:
    """Extract action items using keyword patterns."""
    patterns = [
        r"(?:action|todo|task|follow.?up|next step|will|shall|should|must|needs? to)[:\s]+([^\.\n]{10,80})",
        r"(?:ai|a/i):\s*([^\.\n]{10,80})",
        r"(?:owner|assigned? to|responsible)[:\s]+([^\.\n]{10,80})",
    ]
    items = []
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        items.extend([m.strip().capitalize() for m in matches if len(m.strip()) > 10])
    return list(dict.fromkeys(items))[:6]  # deduplicate, cap at 6


def _extract_decisions(text: str) -> list[str]:
    """Extract decisions from meeting notes."""
    patterns = [
        r"(?:decided?|agreed?|approved?|confirmed?|resolved?|concluded?)[:\s]+([^\.\n]{10,100})",
        r"(?:decision|resolution|conclusion)[:\s]+([^\.\n]{10,100})",
        r"(?:we will|team will|everyone agreed)[:\s]+([^\.\n]{10,100})",
    ]
    decisions = []
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        decisions.extend([m.strip().capitalize() for m in matches if len(m.strip()) > 10])
    return list(dict.fromkeys(decisions))[:5]


def _extract_attendees(text: str) -> list[str]:
    """Extract attendee names (capitalized words that look like names)."""
    # Look for "Attendees:" section first
    att_match = re.search(r"attendees?[:\s]+([^\n]{5,200})", text, re.IGNORECASE)
    if att_match:
        raw = att_match.group(1)
        names = re.split(r"[,;/|]", raw)
        return [n.strip() for n in names if len(n.strip()) > 2][:8]

    # Fallback: capitalized Name patterns
    names = re.findall(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b", text)
    # Filter out common non-name capitalized words
    stopwords = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
                 "January", "February", "March", "April", "May", "June",
                 "July", "August", "September", "October", "November", "December",
                 "Action", "Decision", "Meeting", "Project", "Team", "Please"}
    return [n for n in list(dict.fromkeys(names)) if n not in stopwords][:6]


@tool
def meeting_summary(text: str) -> str:
    """
    Summarize and structure meeting notes for AcmeCorp employees.

    Provide either:
    1. Full meeting notes/minutes — the tool will extract key decisions,
       action items, and attendees into a structured summary.
    2. A meeting topic — the tool will generate a blank meeting template.

    Args:
        text: Meeting notes to summarize, OR a meeting topic for a template

    Returns:
        A structured meeting summary or template
    """
    if not text or not text.strip():
        return "Please provide meeting notes or a topic to summarize."

    text = text.strip()

    # If input is short and looks like a topic (not actual notes)
    if len(text) < 100 and not any(k in text.lower() for k in
                                    ["decided", "agreed", "action", "attendee",
                                     "discussed", "review", "update", "next"]):
        # Generate a meeting template
        today = date.today().strftime("%B %d, %Y")
        return (
            f"## Meeting Template — {text}\n\n"
            f"**Date:** {today}\n"
            f"**Time:** \n"
            f"**Location / Link:** \n"
            f"**Facilitator:** \n\n"
            f"**Attendees:**\n"
            f"  - \n\n"
            f"**Agenda:**\n"
            f"  1. \n"
            f"  2. \n"
            f"  3. \n\n"
            f"**Discussion Points:**\n\n"
            f"**Decisions Made:**\n"
            f"  - \n\n"
            f"**Action Items:**\n"
            f"  | Action | Owner | Due Date |\n"
            f"  |--------|-------|----------|\n"
            f"  |        |       |          |\n\n"
            f"**Next Meeting:** \n"
        )

    # Extract structured info from the notes
    decisions  = _extract_decisions(text)
    actions    = _extract_action_items(text)
    attendees  = _extract_attendees(text)

    # Build word count summary
    word_count = len(text.split())

    output = [f"## Meeting Summary\n*Generated from {word_count}-word notes*\n"]

    if attendees:
        output.append(f"**Attendees:** {', '.join(attendees)}")

    output.append("\n**Key Decisions:**")
    if decisions:
        for d in decisions:
            output.append(f"  ✅ {d}")
    else:
        output.append("  *(No explicit decisions detected — review notes manually)*")

    output.append("\n**Action Items:**")
    if actions:
        for i, a in enumerate(actions, 1):
            output.append(f"  {i}. {a}")
    else:
        output.append("  *(No action items detected — review notes manually)*")

    output.append(
        "\n*Summary generated by Aria — AcmeCorp Internal Assistant. "
        "Please verify against original notes.*"
    )

    return "\n".join(output)