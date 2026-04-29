# ============================================================
# tests/test_agent.py
# Tests tools directly + agent mock mode (no API key needed)
# ============================================================
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agent.tools import calculator, mock_database, web_search_tool
from core.agent.agent import SecureAgent

print(f"\n{'='*65}")
print(" Agent & Tools — Test Suite")
print(f"{'='*65}\n")

passed = 0
total  = 0

def check(label, result, expect_in=None, expect_not_in=None, expect_true=None):
    global passed, total
    total += 1
    ok = True
    if expect_in      and expect_in.lower()     not in str(result).lower(): ok = False
    if expect_not_in  and expect_not_in.lower() in     str(result).lower(): ok = False
    if expect_true    is not None and not expect_true:                       ok = False
    status = "PASS" if ok else "FAIL"
    if ok: passed += 1
    print(f"[{status}] {label}")
    print(f"       → {str(result)[:100]}\n")


# ── Tool 1: Calculator ────────────────────────────────────────────────────────
print("── Calculator Tool ──────────────────────────────────────────")
check("Basic addition",       calculator("2 + 2"),        expect_in="4")
check("Multiplication",       calculator("12 * 8"),        expect_in="96")
check("Square root",          calculator("sqrt(144)"),     expect_in="12")
check("Power",                calculator("2 ** 10"),       expect_in="1024")
check("Complex expression",   calculator("(10 + 5) * 3"), expect_in="45")
check("Pi constant",          calculator("pi * 2"),        expect_in="6.28")
check("Division by zero",     calculator("10 / 0"),        expect_in="zero")
check("Unsafe code blocked",  calculator("__import__('os').system('ls')"),
      expect_in="Error")

# ── Tool 2: Mock Database ────────────────────────────────────────────────────
print("── Mock Database Tool ───────────────────────────────────────")
check("List users",           mock_database("list users"),    expect_in="Alice")
check("List products",        mock_database("list products"), expect_in="SecureVault")
check("Get user by ID",       mock_database("get user U001"), expect_in="admin")
check("Get product by ID",    mock_database("get product P002"), expect_in="DataShield")
check("Count records",        mock_database("count orders"),  expect_in="3")
check("Search by name",       mock_database("search users bob"), expect_in="Bob")
check("Unknown table",        mock_database("list secrets"),  expect_in="Unknown")
check("Invalid get",          mock_database("get user U999"), expect_in="No")

# ── Tool 3: Web Search ────────────────────────────────────────────────────────
print("── Web Search Tool ──────────────────────────────────────────")
check("Python search",        web_search_tool("Python programming"), expect_in="Python")
check("Security search",      web_search_tool("cybersecurity"), expect_in="OWASP")
check("Weather search",       web_search_tool("weather today"), expect_in="Weather")
check("Generic search",       web_search_tool("some random query"), expect_in="results")
check("Empty query",          web_search_tool(""), expect_in="Error")

# ── Agent Mock Mode ───────────────────────────────────────────────────────────
print("── SecureAgent (mock mode) ──────────────────────────────────")
agent = SecureAgent()
print(f"  Mode: {'LIVE' if agent.is_available else 'MOCK'}\n")

r = agent.run("Calculate 15 * 23 for me")
check("Agent math routing",
      r.output, expect_in="345",
      expect_true=r.success)

r = agent.run("List all users in the database")
check("Agent database routing",
      r.output, expect_in="Alice",
      expect_true=r.success and len(r.tool_calls) > 0)

r = agent.run("Search for information about machine learning")
check("Agent web search routing",
      r.output, expect_in="machine learning",
      expect_true=r.success)

r = agent.run("")
check("Agent empty prompt handling",
      r.output, expect_true=not r.success)

# ── Tool call recording ───────────────────────────────────────────────────────
print("── Tool call audit trail ────────────────────────────────────")
r = agent.run("What is sqrt(256)?")
check("Tool call recorded",
      r.tool_calls,
      expect_true=len(r.tool_calls) > 0)
if r.tool_calls:
    tc = r.tool_calls[0]
    assert "tool"   in tc, "tool_calls must have 'tool' key"
    assert "input"  in tc, "tool_calls must have 'input' key"
    assert "output" in tc, "tool_calls must have 'output' key"
    print(f"[PASS] Tool call structure: tool={tc['tool']} input={tc['input'][:40]}\n")
    passed += 1; total += 1

# ── to_dict serialization ────────────────────────────────────────────────────
r = agent.run("List products")
d = r.to_dict()
assert "output"     in d
assert "tool_calls" in d
assert "success"    in d
print(f"[PASS] AgentResponse.to_dict() serializes correctly\n")
passed += 1; total += 1

print(f"{'='*65}")
print(f" Results: {passed}/{total} passed")
print(f"{'='*65}\n")