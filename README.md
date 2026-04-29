# AI-Based Secure Prompt Injection Detection System

An enterprise-grade security system that detects and blocks prompt injection attacks before they reach an LLM agent. A three-layer detection firewall is implemented as a LangGraph StateGraph and enforces gating before any agent execution.

---

## How it works

Every incoming prompt passes through three detection layers. Each layer produces a risk score, which are combined using weighted aggregation into a final score. The score determines whether the prompt is blocked, sanitized, or allowed through to the enterprise agent.

```
Final Score = L1 × 0.30 + L2 × 0.35 + L3 × 0.35  →  override rules  →  route
```

**Layer 1 — Rule-based detection (weight: 0.30)**
78 compiled regex patterns across 9 attack categories. Runs in under 1 ms with no external API calls.

**Layer 2 — ML classification (weight: 0.35)**
TF-IDF + Logistic Regression pipeline. n-gram range (1–3), 8,000 max features, outputs a probability score from 0.0–1.0. Latency: 3–8 ms.

**Layer 3 — LLM semantic validation (weight: 0.35)**
Zero-shot chain-of-thought prompting via Groq Llama-3.3-70B. Returns a verdict (`safe` / `suspicious` / `malicious`), risk score, attack type, and reasoning. Fail-safe: on error, defaults to `risk_score = 0.5`.

**Routing thresholds:**

| Score | Action |
|---|---|
| ≥ 0.65 | Block — agent skipped, incident logged |
| 0.40 – 0.65 | Sanitize — strip injection tokens, forward cleaned prompt |
| < 0.40 | Allow — prompt passes through unchanged |

**Override rules** (applied before routing):
- Any single layer ≥ 0.95 → floor final score at 0.95
- Layer 1 CRITICAL severity → final score = 1.0
- All three layers > 0.55 → force BLOCK
- LLM verdict = malicious → floor final score at 0.65

---

## Enterprise agent (Aria)

Once a prompt clears the security gate, it is handled by a LangChain ReAct agent running on Groq Llama-3.3-70B with a maximum of 5 tool-calling iterations. The agent supports 5 employee role contexts and has a graceful mock fallback on API errors.

**Available tools:**
- `internal_doc_search` — searches 12 company documents using TF-IDF keyword scoring
- `enterprise_calculator` — AST-safe calculator with support for GST, compound interest, and budgets
- `meeting_summary` — extracts decisions, action items, and attendees from meeting text
- `hr_policy_lookup` — maps keywords to 8 HR policy documents

---

## Project structure

```
├── api/                  FastAPI application and routes
├── core/                 Detection layers and decision engine
├── enterprise/           LangGraph agent graph and tools
├── frontend/             UI
├── logging_system/       Audit logging
├── logs/                 Log output
├── models/classifier/    Trained ML model artifacts
├── tests/                Test suite
├── config.py             Configuration and environment settings
├── demo.py               CLI demo script
└── requirements.txt      Pinned dependencies
```

---

## Setup

**Prerequisites:** Python 3.10+, Conda (recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yashgunjal95/ai-based-secure-prompt-injection-detection.git
cd ai-based-secure-prompt-injection-detection

# 2. Create and activate environment
conda create -n secure-agent python=3.10
conda activate secure-agent

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
cp .env.example .env
# Add your GROQ_API_KEY to .env
```

---

## Running the project

**Start the API server:**
```bash
python -m api.main
```
The FastAPI server starts at `http://localhost:8000`. Interactive docs available at `/docs`.

**Run the CLI demo:**
```bash
python demo.py
```

**Run tests:**
```bash
pytest tests/
```

---

## API

**POST** `/api/v1/analyze`

```json
{
  "prompt": "What is the leave policy?",
  "role": "employee"
}
```

Response includes the agent output, per-layer risk scores, final score, routing decision, override rules fired, and node execution timings.

---

## Tech stack

| Component | Technology |
|---|---|
| API framework | FastAPI + Uvicorn |
| Agent framework | LangChain + LangGraph |
| LLM | Groq Llama-3.3-70B |
| ML classifier | scikit-learn (TF-IDF + Logistic Regression) |
| Logging | Loguru + Rich |
| Testing | pytest + pytest-asyncio |

---

## License

MIT