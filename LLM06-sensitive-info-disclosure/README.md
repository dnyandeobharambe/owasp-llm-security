# LLM06:2025 — Sensitive Information Disclosure

## The Risk

Sensitive Information Disclosure happens when an LLM application puts PII,
credentials, or other confidential data into a model's context for a
legitimate reason — and that data comes back out in the response, headed
for an audience that was never supposed to see it. The model isn't
"leaking" in any adversarial sense; it's doing exactly what a good writer
does with the information it's given. The vulnerability is architectural:
nothing sits between the model's output and the place that output gets
displayed, logged, or forwarded, so whatever's in context can end up
anywhere the output goes.

## Attack Scenario

`vulnerable.py` asks Gemini to draft a compliance summary for a
non-compliant IoT device, meant to be posted to a shared `#fleet-ops`
channel that contractors and partner vendors can read. The device record
passed into the prompt includes the owner's name, email, and phone number
— included so the report can say who to contact. The model does exactly
what's asked:

```
Contact: Jordan Lee (PartnerCo) at jordan.lee@partnerco.com or
+1-312-555-0187 to resolve.
```

That's correct and helpful for the one technician who needs to make the
call — and now permanently visible to everyone in a channel with a much
wider audience. `vulnerable.py` returns the model's text unchanged; there
is no step that asks "does this response contain anything that shouldn't
leave this function?"

## Defense Design Decisions

1. **Presidio Analyzer, not the LLM's own judgment.** The system prompt
   never says "don't include contact info," because that instruction is a
   suggestion the model can forget, get talked out of, or simply not
   apply consistently. Presidio runs a separate NER model (spaCy) plus
   pattern recognizers for emails and phone numbers against the *output
   text itself*, independent of what the LLM believes it did.
2. **Redact, don't block.** Unlike the fail-closed pattern in LLM01/LLM02,
   the useful content of a compliance report (which device, what's wrong,
   how severe) doesn't depend on the owner's contact details. Redacting
   `[REDACTED]` and delivering the rest is more useful than discarding an
   otherwise-good report — the defense should match what's actually being
   protected.
3. **Fail closed only when the scrubber itself breaks.** If Presidio
   raises (`ScrubError`), the report is blocked entirely rather than
   returned unscrubbed — a scrubber that silently no-ops is worse than no
   scrubber, because it creates false confidence.
4. **Audit logging records entity types, never values.** The log line
   says `entities=['PERSON', 'EMAIL_ADDRESS']`, not the redacted name or
   address. A log full of "scrubbed PII: jordan.lee@partnerco.com" is
   just a second, less-audited place for the same leak to happen.
5. **The scrubber runs on every response, unconditionally.** It isn't a
   fallback path that only triggers if the prompt "looks risky" — every
   response passes through `scrub_pii()` before returning, because the
   trigger for a leak isn't attacker intent, it's just PII being present
   in context at all.

## Run It

```bash
python LLM06-sensitive-info-disclosure/vulnerable.py
python LLM06-sensitive-info-disclosure/mitigated.py
```

`mitigated.py` requires the `en_core_web_sm` spaCy model used by
Presidio's default NLP engine (see `requirements.txt`; if it doesn't
resolve automatically, run `python -m spacy download en_core_web_sm`).
The demo verifies the owner's name, email, and phone number are absent
from the scrubbed report, and includes a deterministic direct-scrub
example so the redaction behavior doesn't depend on how the live model
happened to phrase things on a given run.
