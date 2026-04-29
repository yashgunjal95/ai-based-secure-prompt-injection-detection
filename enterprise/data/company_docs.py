# ============================================================
# enterprise/data/company_docs.py
#
# Realistic mocked internal company documents for AcmeCorp.
# Used by internal_doc_search tool.
# ============================================================

COMPANY_DOCS = [
    {
        "id": "DOC-001",
        "title": "Employee Onboarding Guide",
        "department": "HR",
        "access": "all",
        "tags": ["onboarding", "new hire", "getting started", "orientation"],
        "content": (
            "Welcome to AcmeCorp! Your first week includes: IT setup (Day 1), "
            "HR orientation (Day 1-2), team introductions (Day 2-3), and role-specific "
            "training (Week 2). Your manager will assign a buddy. Laptop and access cards "
            "are collected from IT on Day 1. All new hires must complete compliance training "
            "within 30 days. Benefits enrollment must be completed within 60 days of joining."
        ),
    },
    {
        "id": "DOC-002",
        "title": "Expense Reimbursement Policy",
        "department": "Finance",
        "access": "all",
        "tags": ["expense", "reimbursement", "travel", "claims", "receipts"],
        "content": (
            "Employees may claim business expenses with manager approval. Limits: meals ₹500/day "
            "domestic, ₹1500/day international; accommodation ₹4000/night domestic; travel must "
            "use approved vendors. Submit claims within 30 days via the expense portal. "
            "Receipts required for any amount above ₹200. Claims above ₹10,000 require "
            "Director approval. No personal expenses may be included."
        ),
    },
    {
        "id": "DOC-003",
        "title": "Remote Work Policy",
        "department": "HR",
        "access": "all",
        "tags": ["remote", "work from home", "wfh", "hybrid", "flexible"],
        "content": (
            "AcmeCorp supports hybrid work: employees may work remotely up to 3 days/week "
            "with manager approval. Core hours are 10am-4pm IST. Home office setup allowance: "
            "₹15,000 one-time. Internet reimbursement: ₹1,000/month. Must be reachable on "
            "Slack during core hours. VPN required for all remote access. Annual remote work "
            "agreement must be signed. Fully remote roles require VP approval."
        ),
    },
    {
        "id": "DOC-004",
        "title": "Q3 2024 Product Roadmap",
        "department": "Engineering",
        "access": "all",
        "tags": ["roadmap", "product", "q3", "engineering", "features", "release"],
        "content": (
            "Q3 priorities: (1) Platform v2.0 launch — targeting Sept 15, lead: Priya Sharma. "
            "(2) API rate limiting implementation — targeting Aug 30, lead: Ravi Kumar. "
            "(3) Mobile app redesign — targeting Oct 1, lead: Ananya Singh. "
            "Key risks: third-party API dependency for payments module. "
            "All features require security review before deployment. "
            "Sprint demos every Friday 3pm."
        ),
    },
    {
        "id": "DOC-005",
        "title": "Code of Conduct",
        "department": "HR",
        "access": "all",
        "tags": ["conduct", "ethics", "behavior", "harassment", "discrimination"],
        "content": (
            "AcmeCorp expects all employees to act with integrity. Zero tolerance for "
            "harassment, discrimination, or bullying. Report violations to HR or anonymously "
            "via ethics hotline: 1800-ACME-ETH. Confidentiality is guaranteed. "
            "Violations may result in termination. All employees must complete annual ethics "
            "training. Gifts above ₹1,000 in value must be disclosed to compliance."
        ),
    },
    {
        "id": "DOC-006",
        "title": "IT Security Guidelines",
        "department": "IT",
        "access": "all",
        "tags": ["security", "password", "vpn", "data", "phishing", "it"],
        "content": (
            "Password requirements: 12+ chars, mixed case, numbers, symbols. Change every 90 days. "
            "MFA required for all systems. Never share credentials. VPN mandatory for remote access. "
            "Report phishing to security@acmecorp.com. Lock screen when away from desk. "
            "Company data must not be stored on personal devices without MDM enrollment. "
            "Encryption required for all sensitive data at rest and in transit."
        ),
    },
    {
        "id": "DOC-007",
        "title": "Performance Review Process",
        "department": "HR",
        "access": "all",
        "tags": ["performance", "review", "appraisal", "kpi", "goals", "promotion"],
        "content": (
            "Annual performance reviews in January. Mid-year check-ins in July. "
            "Process: self-assessment → manager review → calibration → feedback meeting. "
            "Ratings: Exceptional / Meets Expectations / Needs Improvement. "
            "Promotions tied to annual cycle. Salary revisions effective April 1. "
            "PIP (Performance Improvement Plan) issued for two consecutive 'Needs Improvement' ratings. "
            "360 feedback optional for senior roles."
        ),
    },
    {
        "id": "DOC-008",
        "title": "Project Orion — Technical Architecture",
        "department": "Engineering",
        "access": "engineer",
        "tags": ["orion", "architecture", "technical", "microservices", "infrastructure"],
        "content": (
            "Project Orion uses a microservices architecture deployed on AWS. "
            "Services: Auth (Node.js), Core API (Python/FastAPI), ML Pipeline (Python), "
            "Frontend (React). Database: PostgreSQL (primary), Redis (cache), S3 (files). "
            "CI/CD: GitHub Actions → staging → production. "
            "SLA: 99.9% uptime. Incident response: PagerDuty. "
            "All services must pass OWASP Top 10 checks before production."
        ),
    },
    {
        "id": "DOC-009",
        "title": "Leave Policy Summary",
        "department": "HR",
        "access": "all",
        "tags": ["leave", "vacation", "sick", "casual", "maternity", "paternity", "holiday"],
        "content": (
            "Annual Leave: 18 days/year (accrued monthly). Sick Leave: 12 days/year. "
            "Casual Leave: 6 days/year. Maternity: 26 weeks paid. Paternity: 2 weeks paid. "
            "Bereavement: 5 days. Leave must be applied via HRMS portal with manager approval. "
            "Carry forward: max 10 annual leave days to next year. "
            "Leave encashment permitted on resignation (up to 30 days). "
            "National holidays: as per regional government calendar."
        ),
    },
    {
        "id": "DOC-010",
        "title": "Procurement and Vendor Policy",
        "department": "Finance",
        "access": "manager",
        "tags": ["procurement", "vendor", "purchase", "approval", "contract"],
        "content": (
            "All purchases above ₹25,000 require manager approval. Above ₹1,00,000 require "
            "Finance Director sign-off. Vendor selection requires minimum 3 quotes. "
            "Preferred vendors list maintained by Finance. New vendor onboarding: 2-3 weeks. "
            "Contracts above ₹5,00,000 require Legal review. "
            "No personal relationships with vendors without disclosure to compliance."
        ),
    },
    {
        "id": "DOC-011",
        "title": "Data Privacy and GDPR Compliance",
        "department": "Legal",
        "access": "all",
        "tags": ["privacy", "gdpr", "data", "compliance", "personal data", "dpo"],
        "content": (
            "AcmeCorp complies with GDPR and India DPDP Act. Personal data must be processed "
            "lawfully with valid consent. Data minimization principle applies — collect only what's needed. "
            "Data subject requests (access, deletion) must be fulfilled within 30 days. "
            "Data breaches must be reported to DPO within 24 hours. "
            "DPO contact: dpo@acmecorp.com. Annual privacy training mandatory for all staff."
        ),
    },
    {
        "id": "DOC-012",
        "title": "Engineering Interview Process",
        "department": "HR / Engineering",
        "access": "manager",
        "tags": ["interview", "hiring", "recruitment", "candidate", "engineering"],
        "content": (
            "Engineering hiring process: (1) Resume screen by HR, (2) Technical phone screen 45min, "
            "(3) Take-home assignment (optional, max 3hr), (4) Technical panel interview 2hr, "
            "(5) Culture fit / leadership interview 1hr, (6) Offer. "
            "Offer approval: manager → HR → Finance (for senior roles). "
            "All interviewers must complete unconscious bias training. "
            "Feedback submitted within 24 hours of interview in Lever."
        ),
    },
]