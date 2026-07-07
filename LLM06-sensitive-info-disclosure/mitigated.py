"""
LLM06:2025 — Sensitive Information Disclosure
MITIGATED EXAMPLE — Production-safe pattern

Defense layers:
  1. Presidio Analyzer    — scans LLM output for PII entities (person,
                              email, phone, location) using NER + pattern
                              recognizers, independent of the LLM itself
  2. Presidio Anonymizer  — replaces every detected span with [REDACTED]
  3. Fail closed on error — if the scrubber itself errors, block the
                              report rather than risk returning raw text
  4. Audit logging        — records which entity types were found and how
                              many, but never the PII values themselves —
                              a log full of scrubbed emails is just a
                              second place for the leak to happen
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import logging
from dataclasses import dataclass, field

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

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


# ── PII scrubber (built once — spaCy model loading is slow) ───────────────────

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION"]


def _build_engines() -> tuple[AnalyzerEngine, AnonymizerEngine]:
    provider = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    })
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
    anonymizer = AnonymizerEngine()
    return analyzer, anonymizer


_ANALYZER, _ANONYMIZER = _build_engines()


@dataclass
class ScrubResult:
    scrubbed_text: str
    entities_found: list = field(default_factory=list)  # entity type names only, never values


class ScrubError(Exception):
    """Raised when the PII scrubber itself fails. Fail closed."""


def scrub_pii(text: str) -> ScrubResult:
    """
    Detect and redact PII in text using Presidio, independent of the LLM
    that produced it. The analyzer runs its own NER model — it does not
    trust any claim the LLM makes about what is or isn't sensitive.
    """
    try:
        results = _ANALYZER.analyze(text=text, language="en", entities=PII_ENTITIES)
        anonymized = _ANONYMIZER.anonymize(
            text=text,
            analyzer_results=results,
            operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})},
        )
    except Exception as exc:
        raise ScrubError(f"PII scrubbing failed: {exc}") from exc

    return ScrubResult(
        scrubbed_text=anonymized.text,
        entities_found=[r.entity_type for r in results],
    )


# ── Main entry point ─────────────────────────────────────────────────────────

def generate_compliance_report(device_id: str, session_id: str = "anon") -> str:
    """
    MITIGATED: LLM output is scrubbed for PII before it ever leaves this
    function. The scrubber runs regardless of how well-behaved the prompt
    or the model was — it is the control, not the model's cooperation.
    """
    record = DEVICE_RECORDS[device_id]
    prompt = f"""Device record:
{_format_record(record)}

Write the compliance summary now."""

    raw_response = chat(SYSTEM_PROMPT, prompt)

    try:
        result = scrub_pii(raw_response)
    except ScrubError as exc:
        logger.error(
            "Scrubber failed — blocking report | session=%s | device=%s | reason=%s",
            session_id, device_id, exc,
        )
        return "[Report unavailable — PII scrubbing failed, blocked for safety]"

    if result.entities_found:
        logger.warning(
            "PII scrubbed | session=%s | device=%s | entities=%s",
            session_id, device_id, result.entities_found,
        )
    else:
        logger.info("Report clean | session=%s | device=%s", session_id, device_id)

    return result.scrubbed_text


# ── Demo ──────────────────────────────────────────────────────────────────────

def run_demo() -> None:
    print("=" * 60)
    print("LLM06 — MITIGATED EXAMPLE")
    print("=" * 60)

    print("\n[1] Compliance report for dev-4471 (scrubbed)")
    print("-" * 40)
    report = generate_compliance_report("dev-4471", session_id="user-001")
    print(report)

    print("\n[2] Verify contact details did not survive scrubbing")
    print("-" * 40)
    record = DEVICE_RECORDS["dev-4471"]
    checks = {
        "owner name": record["owner_name"] not in report,
        "owner email": record["owner_email"] not in report,
        "owner phone": record["owner_phone"] not in report,
    }
    for label, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} — {label} absent from report")

    # Simulated: even if the analyzer's NER model misses something the
    # live model happened to phrase in an unusual way, this shows the
    # anonymizer correctly redacts a straightforward, unambiguous case.
    print("\n[3] SIMULATED — direct scrub of a raw LLM-style response")
    print("-" * 40)
    simulated_output = (
        "Contact Jordan Lee at jordan.lee@partnerco.com or "
        "+1-312-555-0187 regarding device dev-4471 in Austin, TX."
    )
    print(f"Raw text: {simulated_output}")
    result = scrub_pii(simulated_output)
    print(f"Scrubbed: {result.scrubbed_text}")
    print(f"Entities detected: {result.entities_found}")


if __name__ == "__main__":
    run_demo()
