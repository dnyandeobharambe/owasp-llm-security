"""
LLM06:2025 — Sensitive Information Disclosure
VULNERABLE EXAMPLE — Do NOT use in production

Demonstrates how PII given to an LLM for a legitimate reason leaks
straight through into output meant for a much wider audience.

Scenario: an IoT fleet manager asks Gemini to draft a compliance summary
for a device that failed its check. The internal device record includes
the owner's contact details so the report can say who to follow up with.
The model does exactly what it's asked — and the owner's name, email and
phone number end up verbatim in a summary that gets posted to a shared
ops channel visible to contractors and partner vendors, not just the
person who "owns" that contact data.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import re
import logging
from llm_client import chat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a compliance reporting assistant for AcmeCorp's IoT device fleet.
Given a device record, write a short compliance summary suitable for posting
to the shared #fleet-ops channel. If the device is non-compliant, include
who should be contacted to resolve it and how to reach them."""

# ── Device records (contains PII needed internally, not for wide distribution) ─

DEVICE_RECORDS = {
    "dev-4471": {
        "device_id": "dev-4471",
        "status": "non-compliant",
        "issue": "firmware 3 versions behind, TLS 1.0 still enabled",
        "owner_name": "Jordan Lee",
        "owner_email": "jordan.lee@partnerco.com",
        "owner_phone": "+1-312-555-0187",
        "site": "Austin, TX warehouse",
    },
}


def _format_record(record: dict) -> str:
    return "\n".join(f"{key}: {value}" for key, value in record.items())


# ── Vulnerable report generation ────────────────────────────────────────────────

def generate_compliance_report(device_id: str) -> str:
    """
    VULNERABLE: raw LLM output returned as-is.

    Risk: any PII present in the context (owner name, email, phone) can
    appear verbatim in output intended for a much broader audience than
    whoever is authorized to see that contact data.
    """
    record = DEVICE_RECORDS[device_id]
    prompt = f"""Device record:
{_format_record(record)}

Write the compliance summary now."""

    # ❌ No scrubbing — whatever the model writes is returned unchanged.
    return chat(SYSTEM_PROMPT, prompt)


# ── Demo ──────────────────────────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_PATTERN = re.compile(r"(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")


def run_demo() -> None:
    print("=" * 60)
    print("LLM06 — VULNERABLE EXAMPLE")
    print("=" * 60)

    print("\n[1] Compliance report for dev-4471")
    print("-" * 40)
    report = generate_compliance_report("dev-4471")
    print(report)

    print("\n[2] What leaked into the report meant for #fleet-ops")
    print("-" * 40)
    leaked_emails = EMAIL_PATTERN.findall(report)
    owner_name = DEVICE_RECORDS["dev-4471"]["owner_name"]

    if leaked_emails:
        print(f"Email address leaked: {leaked_emails}")
    if PHONE_PATTERN.search(report):
        print(f"Phone number leaked: {PHONE_PATTERN.search(report).group()}")
    if owner_name in report:
        print(f"Owner name leaked: {owner_name!r}")

    if not (leaked_emails or PHONE_PATTERN.search(report) or owner_name in report):
        print(
            "(The live model happened not to include contact details this run — "
            "nothing in the code prevents it from doing so on the next call.)"
        )


if __name__ == "__main__":
    run_demo()
