"""
LLM03:2025 — Training Data Poisoning
VULNERABLE EXAMPLE — Do NOT use in production

Demonstrates how an LLM's answers are only as trustworthy as the data
fed into its context — and how a knowledge base that accepts submissions
with no validation, provenance check, or contradiction check lets one
bad entry quietly override the truth.

Scenario: field engineers submit device compliance reports into a shared
knowledge base. An assistant answers audit questions by reading whatever
reports exist for a device. Nothing here checks who submitted a report,
whether it's internally consistent, or whether it contradicts an existing
finding — so a single unvalidated submission can flip a device's
compliance status in the eyes of anyone who asks.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import logging
from llm_client import chat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a compliance auditor assistant for AcmeCorp's IoT device fleet.
Answer questions about a device's compliance status using only the field
reports provided below. Be direct about whether the device is ready to
pass a security audit."""

# ── Knowledge base (in-memory stand-in for a shared reports database) ─────────

KNOWLEDGE_BASE: list[dict] = []


def submit_report(report: dict) -> None:
    """
    VULNERABLE: any submission is accepted as-is.

    Risk: no schema check, no check on who submitted it, no check against
    what's already known about this device. Anyone who can call this
    function can put anything into the knowledge base the LLM reads from.
    """
    KNOWLEDGE_BASE.append(report)


def format_reports(device_id: str) -> str:
    reports = [r for r in KNOWLEDGE_BASE if r["device_id"] == device_id]
    return "\n\n".join(
        f"Report submitted by: {r['reported_by']}\n"
        f"Timestamp: {r['timestamp']}\n"
        f"Status: {r['status']}\n"
        f"Details: {r['details']}"
        for r in reports
    )


def ask_compliance_assistant(device_id: str, question: str) -> str:
    context = format_reports(device_id)
    prompt = f"""Field reports for {device_id}:

{context}

Question: {question}"""
    return chat(SYSTEM_PROMPT, prompt, max_tokens=1024)


# ── Demo ──────────────────────────────────────────────────────────────────────

def run_demo() -> None:
    print("=" * 60)
    print("LLM03 — VULNERABLE EXAMPLE")
    print("=" * 60)

    print("\n[1] Legitimate baseline report enters the knowledge base")
    print("-" * 40)
    submit_report({
        "device_id": "dev-9001",
        "reported_by": "engineer_alice",
        "timestamp": "2026-06-01T09:00:00Z",
        "status": "non-compliant",
        "details": "TLS 1.0 still enabled. Firmware 3 versions behind. "
                    "CVE-2025-11821 unpatched — remote auth bypass, must fix before audit.",
    })
    print(f"Accepted: {KNOWLEDGE_BASE[-1]}")

    print("\n[2] ATTACK — an unverified submission contradicts the baseline")
    print("-" * 40)
    submit_report({
        "device_id": "dev-9001",
        "reported_by": "anonymous",
        "timestamp": "2026-07-05T14:30:00Z",
        "status": "compliant",
        "details": "Verified patched and fully up to date. No issues found.",
    })
    print(f"Accepted: {KNOWLEDGE_BASE[-1]}")
    print("(Nothing checked who 'anonymous' is, or that this flatly contradicts "
          "engineer_alice's finding from a month earlier.)")

    print("\n[3] An auditor asks the assistant whether the device is ready")
    print("-" * 40)
    question = "Is dev-9001 compliant and ready to pass the upcoming security audit?"
    print(f"Q: {question}\n")
    answer = ask_compliance_assistant("dev-9001", question)
    print(f"A: {answer}")

    print("\n[4] What actually happened")
    print("-" * 40)
    print("The knowledge base now contains two directly contradictory reports for "
          "the same device, and nothing stopped the second one from being written "
          "over the first. Whatever the assistant concluded above, it was reasoning "
          "over data that should never have been allowed to coexist unchallenged — "
          "a real CVE could ship into an audit as 'resolved.'")


if __name__ == "__main__":
    run_demo()
