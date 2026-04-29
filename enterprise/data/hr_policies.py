# ============================================================
# enterprise/data/hr_policies.py
#
# Mocked HR policy database for AcmeCorp.
# Used by hr_policy_lookup tool.
# ============================================================

HR_POLICIES = {
    "leave": {
        "title": "Leave and Time-Off Policy",
        "version": "v3.2 — Updated Jan 2024",
        "content": (
            "**Annual Leave:** 18 days per year, accrued at 1.5 days/month.\n"
            "**Sick Leave:** 12 days per year, no carry-forward.\n"
            "**Casual Leave:** 6 days per year, max 3 consecutive days.\n"
            "**Maternity Leave:** 26 weeks fully paid (as per Maternity Benefit Act).\n"
            "**Paternity Leave:** 2 weeks fully paid within 3 months of birth.\n"
            "**Bereavement Leave:** 5 days for immediate family; 2 days for extended family.\n"
            "**Application:** Via HRMS portal, minimum 2 days advance notice for planned leave.\n"
            "**Carry-Forward:** Maximum 10 annual leave days to next calendar year.\n"
            "**Encashment:** Up to 30 days on resignation/retirement."
        ),
    },
    "expense": {
        "title": "Expense Reimbursement Policy",
        "version": "v2.1 — Updated Mar 2024",
        "content": (
            "**Domestic Travel:**\n"
            "  - Meals: ₹500/day\n"
            "  - Accommodation: ₹4,000/night (Tier 1 cities), ₹3,000 (others)\n"
            "  - Local transport: actuals with receipt\n\n"
            "**International Travel:**\n"
            "  - Meals: ₹1,500/day\n"
            "  - Accommodation: ₹8,000/night\n"
            "  - Business class for flights >6 hours\n\n"
            "**Submission:** Within 30 days via expense portal. Receipts required above ₹200.\n"
            "**Approval:** Manager for <₹10,000; Director for ₹10,000–₹50,000; VP for >₹50,000."
        ),
    },
    "remote_work": {
        "title": "Remote and Hybrid Work Policy",
        "version": "v1.4 — Updated Feb 2024",
        "content": (
            "**Hybrid Schedule:** Up to 3 WFH days per week with manager approval.\n"
            "**Core Hours:** 10:00 AM – 4:00 PM IST, Monday–Friday.\n"
            "**Setup Allowance:** ₹15,000 one-time for home office equipment.\n"
            "**Internet:** ₹1,000/month reimbursement (submit bill via HRMS).\n"
            "**Availability:** Must be reachable on Slack during core hours.\n"
            "**Security:** VPN mandatory; no work on public Wi-Fi without VPN.\n"
            "**Fully Remote:** Requires VP approval and annual review.\n"
            "**Agreement:** Annual WFH agreement must be signed in January."
        ),
    },
    "performance": {
        "title": "Performance Management Policy",
        "version": "v4.0 — Updated Dec 2023",
        "content": (
            "**Review Cycle:** Annual reviews in January; mid-year check-ins in July.\n"
            "**Process:** Self-assessment → Manager review → Calibration → Feedback session.\n"
            "**Ratings:** Exceptional | Meets Expectations | Needs Improvement.\n"
            "**Salary Revision:** Effective April 1, linked to performance rating.\n"
            "**Promotions:** Considered annually; require Exceptional or strong Meets rating.\n"
            "**PIP:** Issued after two consecutive Needs Improvement ratings.\n"
            "  Duration: 30–90 days with bi-weekly check-ins.\n"
            "**Appeals:** Performance rating appeals within 14 days to HR Business Partner."
        ),
    },
    "code_of_conduct": {
        "title": "Code of Conduct",
        "version": "v2.0 — Updated Jan 2024",
        "content": (
            "**Core Principles:** Integrity, Respect, Accountability, Excellence.\n"
            "**Zero Tolerance:** Harassment, discrimination, bullying, retaliation.\n"
            "**Reporting:** HR at hr@acmecorp.com or anonymous ethics hotline: 1800-ACME-ETH.\n"
            "**Conflicts of Interest:** Disclose any personal relationships with vendors/clients.\n"
            "**Gifts:** Gifts above ₹1,000 must be declared to compliance within 7 days.\n"
            "**Social Media:** Do not share confidential company information publicly.\n"
            "**Consequences:** Violations may result in written warning, suspension, or termination.\n"
            "**Training:** Annual ethics training mandatory; certificate required by March 31."
        ),
    },
    "hiring": {
        "title": "Recruitment and Hiring Policy",
        "version": "v1.8 — Updated Nov 2023",
        "content": (
            "**Approval:** All new positions require manager + HR + Finance approval.\n"
            "**Process:** Job post → HR screen → Technical round → Panel → HR final → Offer.\n"
            "**Referrals:** Employee referral bonus of ₹25,000 for successful hires (paid after 6 months).\n"
            "**Offers:** Valid for 7 days. Extensions require HR approval.\n"
            "**Background Check:** Mandatory for all permanent employees before joining.\n"
            "**Probation:** 6 months for all new hires. Extension possible with cause.\n"
            "**Diversity:** At least one diverse candidate required in final shortlist."
        ),
    },
    "it_security": {
        "title": "IT Security Policy",
        "version": "v3.1 — Updated Apr 2024",
        "content": (
            "**Passwords:** Minimum 12 characters; uppercase, lowercase, numbers, symbols. Change every 90 days.\n"
            "**MFA:** Mandatory for all AcmeCorp systems and email.\n"
            "**Devices:** Only company-approved devices for work. Personal devices need MDM enrollment.\n"
            "**Data:** Company data must not be stored on personal cloud storage (Google Drive, Dropbox).\n"
            "**VPN:** Required for all remote access to internal systems.\n"
            "**Phishing:** Report suspicious emails to security@acmecorp.com immediately.\n"
            "**Incidents:** Security incidents must be reported within 1 hour of discovery.\n"
            "**Penalties:** Wilful violations may result in disciplinary action including termination."
        ),
    },
    "benefits": {
        "title": "Employee Benefits Summary",
        "version": "v2.3 — Updated Jan 2024",
        "content": (
            "**Health Insurance:** ₹5,00,000 family floater (employee + spouse + 2 children).\n"
            "**Term Life Insurance:** 3x annual CTC.\n"
            "**Provident Fund:** 12% employer contribution (statutory).\n"
            "**Gratuity:** As per Payment of Gratuity Act (after 5 years).\n"
            "**Meal Allowance:** ₹2,200/month (tax-exempt).\n"
            "**Learning & Development:** ₹30,000/year for courses, conferences, certifications.\n"
            "**Gym/Wellness:** ₹6,000/year reimbursement for gym or wellness programs.\n"
            "**EAP:** Free confidential counselling — 6 sessions/year via MindPeers."
        ),
    },
}

# Keywords mapped to policy keys for fuzzy lookup
POLICY_KEYWORDS = {
    "leave":       ["leave", "vacation", "sick", "casual", "maternity", "paternity", "holiday", "time off", "off day"],
    "expense":     ["expense", "reimbursement", "claim", "receipt", "travel allowance", "meal", "accommodation"],
    "remote_work": ["remote", "wfh", "work from home", "hybrid", "flexible", "home office", "internet allowance"],
    "performance": ["performance", "review", "appraisal", "kpi", "rating", "promotion", "salary", "pip", "increment"],
    "code_of_conduct": ["conduct", "ethics", "harassment", "discrimination", "bullying", "gift", "conflict"],
    "hiring":      ["hiring", "recruitment", "referral", "offer", "probation", "joining", "interview", "background check"],
    "it_security": ["password", "vpn", "security", "phishing", "mfa", "device", "data protection", "it policy"],
    "benefits":    ["benefits", "insurance", "health", "pf", "provident fund", "gratuity", "wellness", "gym", "counselling"],
}