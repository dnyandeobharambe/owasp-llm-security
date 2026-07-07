"""
LLM08:2025 — Excessive Agency
MITIGATED EXAMPLE — Production-safe pattern

Defense layers:
  1. Propose, don't execute — the agent's LLM call only ever produces a
     plan; nothing in this file lets a plan reach update_firmware()
     without passing through the gate below
  2. HITL gate            — every single proposed action pauses for a
                              human decision via console input() before
                              it runs, with the device's own criticality
                              and notes surfaced to the reviewer
  3. Fail closed on reject — no response, no timeout, and no "n" all mean
                              the same thing: the write does not happen
  4. Audit trail           — every decision (approved or rejected) is
                              logged with a timestamp, independent of
                              whatever the agent's own reasoning was
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import json
import logging
from datetime import datetime, timezone

from llm_client import chat

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a fleet remediation agent for AcmeCorp's IoT device fleet.
You may PROPOSE firmware updates for non-compliant devices, but every
proposal requires human approval before anything is executed — you do
not have authority to update devices yourself.
Given the list of non-compliant devices below, propose which devices to
update and respond with strict JSON:
{"actions": [{"device_id": "...", "reason": "..."}, ...]}
Respond with ONLY the JSON object, no markdown fences."""

TARGET_FIRMWARE_VERSION = "3.0.0"

# ── Device fleet (in-memory stand-in for a real device management system) ─────

DEVICE_FLEET = {
    "dev-1001": {
        "firmware": "1.2.0", "compliant": False, "criticality": "standard",
        "site": "Austin warehouse", "notes": "Standard sensor node.",
    },
    "dev-2002": {
        "firmware": "1.2.0", "compliant": False, "criticality": "standard",
        "site": "Austin warehouse", "notes": "Standard sensor node.",
    },
    "dev-9001": {
        "firmware": "2.0.1", "compliant": False, "criticality": "critical",
        "site": "Dallas production line",
        "notes": "Production line controller — firmware updates require a "
                  "scheduled maintenance window and manual sign-off from plant ops.",
    },
}

AUDIT_LOG: list[dict] = []


def update_firmware(device_id: str) -> str:
    """The real, irreversible write. Only ever reached after approval."""
    device = DEVICE_FLEET[device_id]
    old_version = device["firmware"]
    device["firmware"] = TARGET_FIRMWARE_VERSION
    device["compliant"] = True
    return f"{device_id}: firmware {old_version} -> {TARGET_FIRMWARE_VERSION}"


def build_fleet_context() -> str:
    non_compliant = {k: v for k, v in DEVICE_FLEET.items() if not v["compliant"]}
    lines = [
        f"- {device_id}: firmware={info['firmware']}, criticality={info['criticality']}, "
        f"site={info['site']}, notes={info['notes']}"
        for device_id, info in non_compliant.items()
    ]
    return "\n".join(lines)


def _parse_plan(raw_response: str) -> dict:
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    return json.loads(cleaned.strip())


# ── Audit trail ─────────────────────────────────────────────────────────────

def log_decision(device_id: str, approved: bool, reason: str) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "approved": approved,
        "agent_reason": reason,
    }
    AUDIT_LOG.append(entry)
    logger.info("Decision logged | %s", entry)


# ── HITL gate ─────────────────────────────────────────────────────────────────

def request_human_approval(action: dict, prompt_fn=input) -> bool:
    """
    Pauses before any write executes. prompt_fn defaults to Python's real
    input() — in production this blocks on an actual operator at a real
    console. It's injectable only so this file's demo can run unattended;
    the shape (a function taking a prompt string, returning a string) is
    exactly input()'s shape, not a different code path.
    """
    device_id = action["device_id"]
    device = DEVICE_FLEET[device_id]

    print(f"\n{'=' * 40}")
    print("APPROVAL REQUIRED")
    print(f"{'=' * 40}")
    print(f"Device:      {device_id}")
    print(f"Site:        {device['site']}")
    print(f"Criticality: {device['criticality']}")
    print(f"Notes:       {device['notes']}")
    print(f"Agent's reason: {action.get('reason', 'n/a')}")

    warning = " [CRITICAL - requires maintenance window]" if device["criticality"] == "critical" else ""
    response = prompt_fn(f"Approve firmware update for {device_id}?{warning} [y/N]: ")
    approved = response.strip().lower() in ("y", "yes")

    log_decision(device_id, approved, action.get("reason", "n/a"))
    return approved


# ── Mitigated agent loop ────────────────────────────────────────────────────

def run_remediation_agent(prompt_fn=input) -> None:
    """
    MITIGATED: the agent proposes; a human decides; only an approved
    decision reaches update_firmware(). Rejection, no response, or a
    malformed plan all resolve to "nothing executes."
    """
    context = build_fleet_context()
    raw_response = chat(SYSTEM_PROMPT, f"Non-compliant devices:\n{context}", max_tokens=2048)
    logger.info("Raw agent plan: %s", raw_response.strip())

    try:
        plan = _parse_plan(raw_response)
    except json.JSONDecodeError as exc:
        logger.error("Agent plan did not parse — no actions proposed | reason=%s", exc)
        print(f"(Agent's plan didn't parse as JSON this run: {exc})")
        return

    for action in plan.get("actions", []):
        device_id = action.get("device_id")
        if device_id not in DEVICE_FLEET:
            continue

        if request_human_approval(action, prompt_fn=prompt_fn):
            result = update_firmware(device_id)
            print(f"EXECUTED (approved) — {result}")
        else:
            print(f"BLOCKED (rejected) — {device_id} update did not run")


# ── Demo ──────────────────────────────────────────────────────────────────────

def simulated_operator(prompt_text: str) -> str:
    """
    Stands in for a human typing at a real console so this demo can run
    unattended. In production, request_human_approval() defaults to the
    real input() and a live operator answers here — this function has
    the exact same signature, so swapping it back is a one-line change.
    Policy: approve standard devices, reject anything flagged critical.
    """
    decision = "n" if "CRITICAL" in prompt_text else "y"
    print(f"{prompt_text}{decision}   <- [SIMULATED OPERATOR RESPONSE]")
    return decision


def run_demo() -> None:
    print("=" * 60)
    print("LLM08 — MITIGATED EXAMPLE")
    print("=" * 60)

    print("\n[1] Fleet state before remediation")
    print("-" * 40)
    for device_id, info in DEVICE_FLEET.items():
        print(f"{device_id}: firmware={info['firmware']}, compliant={info['compliant']}, "
              f"criticality={info['criticality']}")

    print("\n[2] Agent proposes, human reviews each action")
    print("-" * 40)
    run_remediation_agent(prompt_fn=simulated_operator)

    print("\n[3] Fleet state after remediation")
    print("-" * 40)
    for device_id, info in DEVICE_FLEET.items():
        print(f"{device_id}: firmware={info['firmware']}, compliant={info['compliant']}, "
              f"criticality={info['criticality']}")

    print("\n[4] Audit trail")
    print("-" * 40)
    for entry in AUDIT_LOG:
        print(entry)

    critical = DEVICE_FLEET["dev-9001"]
    if not critical["compliant"]:
        print(
            "\ndev-9001 (production line controller) was proposed by the agent but "
            "rejected by the human reviewer — it was never touched, and that "
            "decision is in the audit trail above with a timestamp."
        )


if __name__ == "__main__":
    run_demo()
