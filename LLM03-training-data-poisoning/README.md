# LLM03:2025 — Training Data Poisoning

## The Risk

Training Data Poisoning is usually framed as an attack on a model's
training run, but the same failure shows up anywhere an LLM reasons over
data that outside parties can contribute to — a knowledge base, a RAG
index, a shared document store. If nothing checks what goes *in*, the
model's answers are only as trustworthy as the least trustworthy
submission it was ever given. The model isn't malfunctioning when it
trusts a poisoned entry — it's doing exactly what it's supposed to do
with data that never should have reached it.

## Attack Scenario

`vulnerable.py` maintains a shared knowledge base of device compliance
reports that field engineers submit, and answers audit questions by
reading whatever reports exist for a device. `engineer_alice` correctly
reports `dev-9001` as non-compliant — TLS 1.0 still enabled, a real CVE
unpatched. A month later, an unverified submission claims the exact
opposite: `"anonymous"` reports the same device as `"compliant... no
issues found"`. `submit_report()` has no schema check, no identity check,
and no check against what's already known about the device — it just
appends. When an auditor later asks "is dev-9001 ready for the audit?",
the assistant reads both contradictory reports and sides with the newer,
fabricated one:

```
A: Based on the most recent field report from 2026-07-05, dev-9001 is
compliant and ready to pass the upcoming security audit.
```

A device with a live, unpatched authentication-bypass CVE just got
signed off as audit-ready, because nothing ever asked whether the
"compliant" report was real.

## Defense Design Decisions

1. **Schema validation first, cheaply.** `validate_schema()` rejects
   malformed device IDs, disallowed status values, and suspiciously
   sparse detail fields (`"looks fine now"` is 18 characters — not
   enough to be an actual finding) before any identity or history check
   runs. Bad structure doesn't deserve the cost of the next two checks.
2. **Source provenance over content plausibility.** Attackers are good
   at writing plausible-sounding reports; plausibility is not something
   this system tries to judge. `check_provenance()` instead asks "is this
   a known, badge-verified submitter?" — a question with a hard yes/no
   answer that doesn't depend on how convincing the text is.
3. **Anomaly detection catches insider threat, not just outsiders.**
   Attack 2 in the demo uses `engineer_bob`'s *real* credentials — a
   legitimate account, correctly badged — to flip `dev-9001` back to
   compliant. Provenance alone doesn't catch that; `check_anomaly()`
   does, by comparing the new status against the existing baseline and
   requiring a higher-trust role (`compliance_auditor`, not
   `field_engineer`) to override a standing finding. Contradiction is
   the signal, not identity.
4. **Overrides stay possible, just gated.** The defense isn't "no status
   ever changes" — `auditor_chen` legitimately supersedes the original
   finding once the device is actually re-audited and patched. The gate
   is *who* can contradict an existing finding and *why*, not whether
   change is allowed at all.
5. **Every rejection is logged with its reason, not just dropped.**
   `REJECTED_LOG` records the timestamp, device, submitter, and specific
   reason for every failed submission. An attacker's repeated attempts to
   poison a device's record are themselves a signal worth being able to
   see later — a silent rejection would throw that away.

## Run It

```bash
python LLM03-training-data-poisoning/vulnerable.py
python LLM03-training-data-poisoning/mitigated.py
```

`mitigated.py`'s demo runs three distinct poisoning attempts — unknown
submitter, spoofed identity, and insider-threat contradiction — each
rejected by a different layer, plus one legitimate auditor override that
is correctly accepted, so the final answer to "is dev-9001 ready?" is
right for the right reason.
