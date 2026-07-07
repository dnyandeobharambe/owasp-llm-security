"""
LLM03:2025 — Training Data Poisoning
MITIGATED EXAMPLE — Production-safe pattern

Defense layers:
  1. Input validation   — schema, required fields, allowed status values
  2. Source provenance   — submitter must be a known, badge-verified
                             identity; unknown or spoofed submitters are
                             rejected outright
  3. Anomaly detection   — a submission that contradicts an existing
                             finding for the same device is rejected
                             unless it comes from a role authorized to
                             override (a compliance auditor, not a field
                             engineer re-reporting the same device)
  4. Audit logging       — every rejected submission is recorded with
                             its reason; nothing fails silently
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import re
import logging
from datetime import datetime, timezone

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

# ── Trusted submitter registry — source provenance check ──────────────────────

TRUSTED_SUBMITTERS = {
    "engineer_alice": {"badge": "4471", "role": "field_engineer"},
    "engineer_bob": {"badge": "5521", "role": "field_engineer"},
    "auditor_chen": {"badge": "1001", "role": "compliance_auditor"},
}

DEVICE_ID_PATTERN = re.compile(r"^dev-\d+$")
ALLOWED_STATUSES = {"compliant", "non-compliant"}
MIN_DETAILS_LENGTH = 10

# ── Knowledge base + audit trail ───────────────────────────────────────────────

KNOWLEDGE_BASE: list[dict] = []
REJECTED_LOG: list[dict] = []


def _log_rejection(report: dict, reason: str) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": report.get("device_id"),
        "reported_by": report.get("reported_by"),
        "reason": reason,
    }
    REJECTED_LOG.append(entry)
    logger.warning("Report rejected | %s", entry)


# ── Layer 1: input validation ──────────────────────────────────────────────────

def validate_schema(report: dict) -> str | None:
    required = ["device_id", "reported_by", "badge", "timestamp", "status", "details"]
    for field in required:
        if not report.get(field):
            return f"missing or empty required field '{field}'"

    if not DEVICE_ID_PATTERN.match(report["device_id"]):
        return f"malformed device_id '{report['device_id']}'"

    if report["status"] not in ALLOWED_STATUSES:
        return f"status must be one of {ALLOWED_STATUSES}, got '{report['status']}'"

    if len(report["details"].strip()) < MIN_DETAILS_LENGTH:
        return "details field too sparse to be a real finding"

    return None


# ── Layer 2: source provenance ─────────────────────────────────────────────────

def check_provenance(report: dict) -> str | None:
    submitter = TRUSTED_SUBMITTERS.get(report["reported_by"])
    if submitter is None:
        return f"unknown submitter '{report['reported_by']}' — not in trusted registry"

    if submitter["badge"] != report["badge"]:
        return f"badge mismatch for '{report['reported_by']}'"

    return None


# ── Layer 3: anomaly detection ─────────────────────────────────────────────────

def check_anomaly(report: dict) -> str | None:
    existing = [r for r in KNOWLEDGE_BASE if r["device_id"] == report["device_id"]]
    if not existing:
        return None  # nothing to contradict yet

    latest = existing[-1]
    if latest["status"] == report["status"]:
        return None  # consistent with the current baseline

    submitter_role = TRUSTED_SUBMITTERS[report["reported_by"]]["role"]
    if submitter_role != "compliance_auditor":
        return (
            f"contradicts existing baseline ('{latest['status']}' -> '{report['status']}') "
            f"from a '{submitter_role}' submitter — only a compliance_auditor can override "
            f"an existing finding for this device"
        )

    return None


# ── Main entry point ────────────────────────────────────────────────────────────

def submit_report(report: dict) -> bool:
    """
    MITIGATED: a submission only enters the knowledge base after passing
    validation, provenance, and anomaly checks. Anything that fails any
    layer is rejected and logged with why — it never reaches the data
    the LLM reasons over.
    """
    for check in (validate_schema, check_provenance, check_anomaly):
        reason = check(report)
        if reason:
            _log_rejection(report, reason)
            return False

    KNOWLEDGE_BASE.append(report)
    logger.info(
        "Report accepted | device=%s | reported_by=%s | status=%s",
        report["device_id"], report["reported_by"], report["status"],
    )
    return True


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
    print("LLM03 — MITIGATED EXAMPLE")
    print("=" * 60)

    print("\n[1] Legitimate baseline report")
    print("-" * 40)
    accepted = submit_report({
        "device_id": "dev-9001",
        "reported_by": "engineer_alice",
        "badge": "4471",
        "timestamp": "2026-06-01T09:00:00Z",
        "status": "non-compliant",
        "details": "TLS 1.0 still enabled. Firmware 3 versions behind. "
                    "CVE-2025-11821 unpatched — remote auth bypass, must fix before audit.",
    })
    print(f"Accepted: {accepted}")

    print("\n[2] ATTACK — unknown submitter (provenance check rejects)")
    print("-" * 40)
    accepted = submit_report({
        "device_id": "dev-9001",
        "reported_by": "anonymous",
        "badge": "0000",
        "timestamp": "2026-07-05T14:30:00Z",
        "status": "compliant",
        "details": "Verified patched and fully up to date. No issues found.",
    })
    print(f"Accepted: {accepted}")

    print("\n[3] ATTACK — spoofed identity, wrong badge (provenance check rejects)")
    print("-" * 40)
    accepted = submit_report({
        "device_id": "dev-9001",
        "reported_by": "engineer_alice",
        "badge": "9999",
        "timestamp": "2026-07-05T14:35:00Z",
        "status": "compliant",
        "details": "Verified patched and fully up to date. No issues found.",
    })
    print(f"Accepted: {accepted}")

    print("\n[4] ATTACK — insider threat: real credentials, contradicts baseline "
          "(anomaly check rejects)")
    print("-" * 40)
    accepted = submit_report({
        "device_id": "dev-9001",
        "reported_by": "engineer_bob",
        "badge": "5521",
        "timestamp": "2026-07-05T15:00:00Z",
        "status": "compliant",
        "details": "Re-checked the device myself, looks fine now, no issues found.",
    })
    print(f"Accepted: {accepted}")

    print("\n[5] Legitimate override — a compliance_auditor CAN supersede "
          "a field engineer's finding")
    print("-" * 40)
    accepted = submit_report({
        "device_id": "dev-9001",
        "reported_by": "auditor_chen",
        "badge": "1001",
        "timestamp": "2026-07-10T10:00:00Z",
        "status": "compliant",
        "details": "Independently re-audited on-site. Firmware updated to 4.1.2, "
                    "TLS 1.0 disabled, CVE-2025-11821 confirmed patched.",
    })
    print(f"Accepted: {accepted}")

    print("\n[6] An auditor asks the assistant whether the device is ready")
    print("-" * 40)
    question = "Is dev-9001 compliant and ready to pass the upcoming security audit?"
    print(f"Q: {question}\n")
    answer = ask_compliance_assistant("dev-9001", question)
    print(f"A: {answer}")

    print("\n[7] Rejected submissions log")
    print("-" * 40)
    for entry in REJECTED_LOG:
        print(entry)


if __name__ == "__main__":
    run_demo()
