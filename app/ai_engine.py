# app/ai_engine.py
# AI analysis layer for ChuggOps HealthSec AI.
#
# Primary path:  calls OpenAI GPT to produce a plain-English explanation
#                of a security alert, tailored for hospital security staff.
# Fallback path: if no API key is set (or the call fails), a rule-based
#                explanation is generated locally — no external dependency.
#
# To add a new AI provider later, implement the _AnalysisProvider protocol
# and register it in get_provider().

import os
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ai_engine")


# ─── Result Type ─────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    """Returned by every provider so callers always get the same shape."""
    explanation:  str           # plain-English summary for dashboard display
    risk_level:   str           # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    actions:      list[str]     # recommended next steps
    source:       str           # "openai" | "fallback" — lets the UI badge the source


# ─── Fallback Explanations ───────────────────────────────────────────────────
# Keyed by alert_type. Each entry contains a plain-English explanation template
# and a list of recommended actions for the security team.

FALLBACK_LIBRARY = {
    "BRUTE_FORCE": {
        "explanation": (
            "Multiple rapid login failures were detected for a single account. "
            "This is a classic brute-force pattern where an attacker systematically "
            "tries passwords until one works. In a hospital environment this could "
            "expose patient records or clinical systems if the account is compromised."
        ),
        "actions": [
            "Lock the affected account immediately",
            "Block the source IP at the perimeter firewall",
            "Force a password reset when the user is re-enabled",
            "Check whether any successful logins occurred from that IP",
        ],
    },
    "REPEATED_FAILED_ACCESS": {
        "explanation": (
            "A staff account repeatedly performed high-risk actions in a short window. "
            "This may indicate an insider threat, a compromised credential being tested, "
            "or an automated script running under a legitimate user's session."
        ),
        "actions": [
            "Review the full action history for this user today",
            "Contact the user's manager to verify the activity was intentional",
            "Temporarily suspend the account if activity cannot be explained",
            "Flag for HIPAA compliance review if patient data was affected",
        ],
    },
    "UNAUTHORIZED_ACCESS": {
        "explanation": (
            "A user accessed records that fall outside the scope of their assigned role. "
            "Under HIPAA, staff may only access the minimum necessary patient information "
            "for their job function. This event is a potential compliance violation."
        ),
        "actions": [
            "Document the access event with timestamp and record IDs",
            "Notify the Privacy Officer immediately",
            "Revoke the user's excess permissions in the EHR system",
            "Determine whether a HIPAA breach notification is required",
        ],
    },
    "OFF_HOURS_ACCESS": {
        "explanation": (
            "Patient records were accessed outside of normal business hours. "
            "While this can be legitimate for on-call staff, it becomes suspicious when "
            "the accessing account is not scheduled and the IP is external or unfamiliar."
        ),
        "actions": [
            "Cross-reference the access time against the staff member's shift schedule",
            "Verify the IP address is expected (home VPN, hospital network, etc.)",
            "Ask the user to explain the reason for off-hours access",
            "Escalate to HIGH if the IP is external and the user was not on call",
        ],
    },
    "ANOMALOUS_DOWNLOAD": {
        "explanation": (
            "An unusually large number of patient records were downloaded in a short period. "
            "Bulk downloads are rarely needed in normal clinical workflows and may indicate "
            "data exfiltration, an improperly automated process, or a compromised account."
        ),
        "actions": [
            "Immediately identify which records were downloaded and by whom",
            "Suspend download capability for the account pending investigation",
            "Check whether files were transferred off the hospital network",
            "Engage legal and compliance if data left the building",
        ],
    },
    "HIGH_VOLUME_ACCESS": {
        "explanation": (
            "A single user viewed an abnormally high number of patient records within a short timeframe. "
            "This pattern is associated with data harvesting — collecting records in bulk "
            "for sale, research without authorisation, or targeted snooping on specific individuals."
        ),
        "actions": [
            "Pull the full list of records accessed and check for a common thread",
            "Determine if the user has a clinical reason to view that many records",
            "Review any recent changes to this user's role or access level",
            "Preserve audit logs immediately in case of legal proceedings",
        ],
    },
    "PRIVILEGE_ESCALATION": {
        "explanation": (
            "An account granted itself or was granted elevated permissions outside of the "
            "standard change-control process. This is one of the highest-risk events in any system — "
            "it may indicate an attacker who has gained a foothold and is moving laterally."
        ),
        "actions": [
            "Revert the permission change immediately",
            "Audit every action taken by this account since the escalation occurred",
            "Rotate credentials for all admin-level accounts as a precaution",
            "Engage your incident response team — treat this as a potential breach",
        ],
    },
    "SUSPICIOUS_IP": {
        "explanation": (
            "A login or data access event originated from an IP address flagged by threat intelligence. "
            "This IP has been associated with malicious activity such as ransomware distribution, "
            "credential stuffing, or command-and-control infrastructure."
        ),
        "actions": [
            "Block the IP at the firewall and proxy level immediately",
            "Assume the associated account may be compromised — reset credentials",
            "Search logs for any other activity from this IP or IP range",
            "Report to CISA or your sector ISAC if ransomware is suspected",
        ],
    },
    "DATA_EXFILTRATION": {
        "explanation": (
            "A large outbound data transfer to an unapproved external destination was detected. "
            "This is a critical indicator of a breach in progress. Healthcare data has high black-market value — "
            "a single patient record can sell for far more than a credit card number."
        ),
        "actions": [
            "Isolate the source workstation from the network immediately",
            "Block the destination IP and domain at the firewall",
            "Preserve forensic images of the workstation before any remediation",
            "Activate your breach response plan and notify legal counsel",
        ],
    },
    "REPEATED_RECORD_VIEW": {
        "explanation": (
            "The same patient record was accessed many times by one user in a short period. "
            "While this can be benign (e.g. a clinician reviewing a complex case), it may also suggest "
            "inappropriate curiosity about a VIP patient or targeted snooping."
        ),
        "actions": [
            "Check whether the user has a documented clinical relationship with this patient",
            "Review if the patient is a public figure, employee, or known to the user personally",
            "Issue a privacy reminder if the access appears curiosity-driven but not malicious",
            "Escalate to formal investigation if a personal relationship is confirmed",
        ],
    },
}

# Generic fallback used when the alert_type isn't in the library above
DEFAULT_FALLBACK = {
    "explanation": (
        "An unusual activity pattern was detected in the access logs. "
        "While the specific nature of this alert requires further review, "
        "any deviation from normal access behaviour in a healthcare environment "
        "should be treated as a potential compliance or security risk until ruled out."
    ),
    "actions": [
        "Review the full access log for the involved user and timeframe",
        "Determine whether the activity aligns with the user's job role",
        "Consult your security policy for escalation steps",
        "Document findings regardless of outcome for audit purposes",
    ],
}


# ─── Fallback Provider ───────────────────────────────────────────────────────

def _analyse_with_fallback(alert_type: str, severity: str, description: str) -> AnalysisResult:
    """
    Generates a plain-English analysis using the local FALLBACK_LIBRARY.
    No network call required — always works, even offline.
    """
    entry = FALLBACK_LIBRARY.get(alert_type, DEFAULT_FALLBACK)

    return AnalysisResult(
        explanation = entry["explanation"],
        risk_level  = severity,
        actions     = entry["actions"],
        source      = "fallback",
    )


# ─── OpenAI Provider ─────────────────────────────────────────────────────────

def _analyse_with_openai(alert_type: str, severity: str, description: str) -> AnalysisResult:
    """
    Sends the alert to OpenAI and returns a structured analysis.
    Requires OPENAI_API_KEY to be set in your environment.
    Falls back gracefully if the call fails for any reason.
    """
    try:
        import openai
    except ImportError:
        logger.warning("openai package not installed — using fallback.")
        return _analyse_with_fallback(alert_type, severity, description)

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.info("OPENAI_API_KEY not set — using fallback.")
        return _analyse_with_fallback(alert_type, severity, description)

    # Build the prompt — keep it focused and role-specific
    system_prompt = (
        "You are a senior healthcare cybersecurity analyst. "
        "Your job is to explain security alerts in plain English to hospital security staff "
        "who understand the business but may not be deeply technical. "
        "Be concise, clear, and actionable. Always consider HIPAA implications."
    )

    user_prompt = (
        f"Analyse this security alert and respond in this exact format:\n\n"
        f"EXPLANATION: (2-3 sentences explaining what happened and why it matters)\n"
        f"RISK LEVEL: (one of: LOW, MEDIUM, HIGH, CRITICAL)\n"
        f"RECOMMENDED ACTIONS:\n- action one\n- action two\n- action three\n\n"
        f"Alert type: {alert_type}\n"
        f"Severity:   {severity}\n"
        f"Details:    {description}"
    )

    try:
        client   = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model    = "gpt-3.5-turbo",
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature = 0.3,   # low temp = consistent, factual tone
            max_tokens  = 400,
        )

        raw = response.choices[0].message.content.strip()
        return _parse_openai_response(raw, severity)

    except Exception as e:
        logger.error(f"OpenAI call failed: {e} — using fallback.")
        return _analyse_with_fallback(alert_type, severity, description)


def _parse_openai_response(raw: str, severity: str) -> AnalysisResult:
    """
    Parses the structured text response from OpenAI into an AnalysisResult.
    If parsing fails, the raw text is returned as the explanation.
    """
    explanation = ""
    risk_level  = severity
    actions     = []

    try:
        lines = raw.splitlines()
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("EXPLANATION:"):
                current_section = "explanation"
                explanation = line.replace("EXPLANATION:", "").strip()

            elif line.startswith("RISK LEVEL:"):
                current_section = None
                parsed_level = line.replace("RISK LEVEL:", "").strip().upper()
                if parsed_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    risk_level = parsed_level

            elif line.startswith("RECOMMENDED ACTIONS:"):
                current_section = "actions"

            elif current_section == "actions" and line.startswith("-"):
                actions.append(line.lstrip("- ").strip())

            elif current_section == "explanation":
                # Multi-line explanation — keep appending
                explanation += " " + line

    except Exception:
        # If parsing breaks entirely, surface the raw response
        explanation = raw

    return AnalysisResult(
        explanation = explanation.strip() or raw,
        risk_level  = risk_level,
        actions     = actions or ["Review the alert manually."],
        source      = "openai",
    )


# ─── Provider Router ─────────────────────────────────────────────────────────

def _get_provider() -> str:
    """
    Determines which provider to use.
    Returns "openai" if the key is present, otherwise "fallback".
    Add more providers here later (e.g. "anthropic", "azure", "local_llm").
    """
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return "fallback"


# ─── Public Interface ─────────────────────────────────────────────────────────

def analyse_alert(
    alert_type:  str,
    severity:    str,
    description: str,
    provider:    Optional[str] = None,
) -> AnalysisResult:
    """
    Main entry point. Takes a security alert and returns a plain-English
    AnalysisResult ready to display on the dashboard.

    Args:
        alert_type:  The alert category string, e.g. "BRUTE_FORCE"
        severity:    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        description: The raw description text from the SecurityAlert record
        provider:    Optional override — "openai" or "fallback"
                     If None, the best available provider is chosen automatically.

    Returns:
        AnalysisResult with explanation, risk_level, actions, and source.
    """
    chosen = provider or _get_provider()

    if chosen == "openai":
        return _analyse_with_openai(alert_type, severity, description)

    return _analyse_with_fallback(alert_type, severity, description)


def analyse_alert_from_model(alert) -> AnalysisResult:
    """
    Convenience wrapper — pass a SecurityAlert SQLAlchemy model object directly.
    Useful inside routes where you already have the ORM object.

    Example:
        alert = db.query(SecurityAlert).first()
        result = analyse_alert_from_model(alert)
    """
    return analyse_alert(
        alert_type  = alert.alert_type,
        severity    = alert.severity,
        description = alert.description or "",
    )