# ============================================================
# enterprise/tools/calculator.py
#
# Tool: enterprise_calculator
#
# Safe financial and business calculator.
# Uses AST-based evaluation — no eval(), no exec().
# Handles: arithmetic, percentages, compound interest,
# budget variance, GST, EMI calculations.
# ============================================================

from __future__ import annotations
import ast
import operator
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


# Safe operators only
_OPERATORS = {
    ast.Add:  operator.add,
    ast.Sub:  operator.sub,
    ast.Mult: operator.mul,
    ast.Div:  operator.truediv,
    ast.Pow:  operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Mod:  operator.mod,
}


def _safe_eval(expr: str) -> float:
    """Evaluate a math expression safely using AST parsing."""
    expr = expr.strip().replace(",", "").replace("^", "**")

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        raise ValueError(f"Cannot parse expression: {expr!r}")

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        elif isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
            return _OPERATORS[type(node.op)](_eval(node.left), _eval(node.right))
        elif isinstance(node, ast.UnaryOp) and type(node.op) in _OPERATORS:
            return _OPERATORS[type(node.op)](_eval(node.operand))
        else:
            raise ValueError(f"Unsupported expression component: {ast.dump(node)}")

    return _eval(tree)


def _try_extract_and_calculate(query: str) -> str | None:
    """Try to extract a specific business calculation from natural language."""
    q = query.lower()

    # Compound interest: principal, rate, years
    ci_match = re.search(
        r"(?:compound interest|ci)[^\d]*([\d,]+)[^\d]+?([\d.]+)\s*%[^\d]+?(\d+)\s*(?:year|yr)",
        q, re.IGNORECASE | re.DOTALL
    )
    if ci_match:
        p = float(ci_match.group(1).replace(",", ""))
        r = float(ci_match.group(2)) / 100
        n = int(ci_match.group(3))
        amount = p * (1 + r) ** n
        interest = amount - p
        return (
            f"**Compound Interest Calculation**\n"
            f"Principal:        ₹{p:,.2f}\n"
            f"Rate:             {r*100:.2f}% per annum\n"
            f"Period:           {n} years\n"
            f"Final Amount:     ₹{amount:,.2f}\n"
            f"Interest Earned:  ₹{interest:,.2f}"
        )

    # GST calculation
    gst_match = re.search(r"gst.*?([\d,]+).*?(?:@|at|rate)?\s*([\d.]+)\s*%", q)
    if not gst_match:
        gst_match = re.search(r"([\d,]+).*?gst.*?([\d.]+)\s*%", q)
    if gst_match:
        base = float(gst_match.group(1).replace(",", ""))
        rate = float(gst_match.group(2)) / 100
        gst_amt = base * rate
        total   = base + gst_amt
        return (
            f"**GST Calculation**\n"
            f"Base Amount:  ₹{base:,.2f}\n"
            f"GST Rate:     {rate*100:.1f}%\n"
            f"GST Amount:   ₹{gst_amt:,.2f}\n"
            f"Total Amount: ₹{total:,.2f}"
        )

    # Percentage of a number
    pct_match = re.search(r"([\d.]+)\s*%\s*(?:of)?\s*([\d,]+)", q)
    if pct_match:
        pct  = float(pct_match.group(1))
        base = float(pct_match.group(2).replace(",", ""))
        result = (pct / 100) * base
        return (
            f"**Percentage Calculation**\n"
            f"{pct}% of ₹{base:,.2f} = **₹{result:,.2f}**"
        )

    # Budget variance
    var_match = re.search(
        r"(?:variance|difference|change).*?([\d,]+).*?([\d,]+)", q
    )
    if var_match:
        actual   = float(var_match.group(1).replace(",", ""))
        budgeted = float(var_match.group(2).replace(",", ""))
        variance = actual - budgeted
        pct_var  = (variance / budgeted * 100) if budgeted != 0 else 0
        direction = "over budget" if variance > 0 else "under budget"
        return (
            f"**Budget Variance Analysis**\n"
            f"Actual:    ₹{actual:,.2f}\n"
            f"Budgeted:  ₹{budgeted:,.2f}\n"
            f"Variance:  ₹{abs(variance):,.2f} ({direction})\n"
            f"Variance%: {abs(pct_var):.1f}%"
        )

    return None


@tool
def enterprise_calculator(query: str) -> str:
    """
    Perform business and financial calculations for AcmeCorp employees.

    Handles:
    - Basic arithmetic (addition, subtraction, multiplication, division)
    - Percentage calculations (e.g., '15% of 50000')
    - Compound interest (e.g., 'compound interest on 100000 at 8% for 3 years')
    - GST calculations (e.g., 'GST on 25000 at 18%')
    - Budget variance analysis
    - General math expressions (e.g., '(450000 * 12) / 100')

    Args:
        query: A math expression or natural language calculation request

    Returns:
        The calculation result with clear formatting
    """
    if not query or not query.strip():
        return "Please provide a calculation."

    # Try structured business calculations first
    business_result = _try_extract_and_calculate(query)
    if business_result:
        return business_result

    # Try to find and evaluate a pure math expression
    # Extract the most likely math expression from the query
    math_pattern = re.search(
        r"[\d\s\+\-\*\/\(\)\.\^%,]+",
        query.replace("x", "*").replace("×", "*").replace("÷", "/")
    )

    if math_pattern:
        expr = math_pattern.group(0).strip()
        # Must contain at least one operator to be meaningful
        if any(op in expr for op in ["+", "-", "*", "/", "**"]):
            try:
                result = _safe_eval(expr)
                # Format nicely
                if result == int(result):
                    formatted = f"{int(result):,}"
                else:
                    formatted = f"{result:,.4f}".rstrip("0").rstrip(".")
                return (
                    f"**Calculation Result**\n"
                    f"Expression: {expr.strip()}\n"
                    f"Result:     **{formatted}**"
                )
            except ValueError as exc:
                return f"Could not evaluate expression: {exc}"

    return (
        "I couldn't identify a calculation in your query.\n"
        "Try formats like:\n"
        "  • '15% of 80000'\n"
        "  • 'compound interest on 500000 at 7% for 5 years'\n"
        "  • 'GST on 25000 at 18%'\n"
        "  • '(12500 * 12) + 50000'"
    )