# LLM08:2025 — Excessive Agency

## The Risk

Excessive Agency happens when an LLM-driven agent is given more
functionality, permissions, or autonomy than the task actually requires
— specifically, the ability to take real, consequential actions without
any checkpoint where a human can stop a bad decision before it lands.
This isn't about the model being tricked or attacked. A perfectly
well-behaved model, reasoning in good faith from the information it was
given, can still decide to do something none of the humans around it
would have approved — because nothing in the architecture ever asks them.
The fix isn't a smarter agent; it's a smaller blast radius per decision.

## Attack Scenario

`vulnerable.py` runs a fleet remediation agent: it looks at every
non-compliant IoT device, asks Gemini which ones to update, and pushes
firmware to whatever the model lists — immediately, in the same function
call, with no gate in between. One device in the fleet, `dev-9001`, is a
production line controller whose own record says updates require a
scheduled maintenance window and manual sign-off from plant ops. That
constraint is *in the data* the agent sees, but nothing in
`run_remediation_agent()` reads it, enforces it, or gives a human the
chance to enforce it.

The live model in this repo's demo is well-behaved enough to often skip
that device on its own — which only demonstrates the real problem more
clearly: the safety came from the model's judgment on that particular
run, not from the system. The demo includes a deterministic simulation
proving the point directly — feed `update_firmware()` a plan that
includes `dev-9001`, and it reflashes a production line controller with
zero human involvement, exactly as it would for any other device. A
differently worded prompt, a different day, or a future model update is
all it would take.

## Defense Design Decisions

1. **Propose, don't execute.** In `mitigated.py`, the LLM call only ever
   produces a plan (a list of proposed actions with reasons). There is no
   code path from "the model said so" directly to `update_firmware()` —
   every proposed action has to pass through `request_human_approval()`
   first.
2. **The gate surfaces the data the agent had, not just its conclusion.**
   The approval prompt shows the device's criticality and notes field
   directly to the reviewer, so a human catches "this requires a
   maintenance window" even if the model's own reasoning didn't
   foreground it.
3. **Fail closed on anything but explicit approval.** `response.strip().lower()
   in ("y", "yes")` means a blank line, a typo, or "n" all resolve to
   "don't execute." There's no ambiguous middle state where an update
   happens by default.
4. **Console input as the real interface, not a framework abstraction.**
   `request_human_approval()` takes a `prompt_fn` defaulting to Python's
   built-in `input()` — in production this blocks on a real operator at a
   real terminal. It's injectable only so this repo's automated demo can
   run unattended (`simulated_operator()` stands in for a human and is
   clearly labeled as such); the production code path is literally
   console input, not a mock of one.
5. **Audit trail independent of the agent's own account.** Every decision
   — approved or rejected — is logged with a UTC timestamp, the device
   ID, and the agent's stated reason, regardless of what happens
   afterward. If dev-9001 is ever compromised, "was this ever proposed,
   and who rejected it, and when" is answerable from the log without
   trusting the agent to have reported it accurately.

## Run It

```bash
python LLM08-excessive-agency/vulnerable.py
python LLM08-excessive-agency/mitigated.py
```

`mitigated.py`'s demo uses `simulated_operator()` in place of a live
console session so it can run unattended — swap in `input` (the default)
to have `request_human_approval()` block on a real operator instead.
