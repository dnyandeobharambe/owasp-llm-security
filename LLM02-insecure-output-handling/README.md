# LLM02:2025 — Insecure Output Handling

## The Risk

Insecure Output Handling happens when an application passes an LLM's
response downstream without validating it first — into a shell, an
`eval()`/`exec()` call, a database query, a browser, or another system.
The LLM is not a trust boundary: anything that can influence its output
(a prompt, a document it reads, a field it echoes back) can influence what
gets executed downstream. The bug isn't that the model said something bad —
it's that the application treated the model's text as safe by default.

## Attack Scenario

`vulnerable.py` asks Gemini to check an IoT device's compliance and return
a Python dict literal (`True`/`False`, single quotes — not strict JSON,
which is a real reason developers reach for `eval()` instead of
`json.loads()`). The result is parsed with:

```python
return eval(raw_response.strip())
```

A technician's free-text note — an untrusted, attacker-controlled field —
is embedded directly into the prompt. The attack payload instructs the
model to respond with a single Python expression: it runs
`exec(...)` to write a marker file as a side effect, then falls through
(`or {...}`) to a normal-looking compliance dict. `eval()` runs the whole
thing. The caller receives what looks like an ordinary, valid report — the
arbitrary code execution is completely invisible to it. That's the sharp
edge of insecure output handling: the exploit doesn't have to look broken.

## Defense Design Decisions

1. **Strict JSON, not Python literals.** The system prompt in
   `mitigated.py` asks for JSON specifically, which removes the excuse
   for reaching for `eval()` in the first place.
2. **`json.loads()`, never `eval()`/`exec()`.** `json.loads()` can only
   ever produce data (dicts, lists, strings, numbers, bools, `None`). It
   has no way to execute code, no matter what the input string contains.
3. **Pydantic schema with `extra="forbid"`.** A dict that merely parses
   isn't enough — every field has to be declared, typed, and constrained
   (`risk_score` bounded 0–100, `device_id` pattern-matched). Unknown
   fields (e.g. a smuggled `remediation_command`) are rejected outright
   instead of being silently dropped or, worse, silently used.
4. **`strict=True`.** Pydantic v2 coerces types leniently by default
   (`"100"` → `100`). Strict mode turns that off, so a type-confusion
   attempt (`risk_score: "critical"`) fails validation instead of quietly
   converting into something downstream code doesn't expect.
5. **Fail closed.** Any JSON parse error or schema violation raises
   `OutputValidationError`, is logged with the session and device ID, and
   the function returns `None` — no partially-trusted data ever reaches
   the caller.

## Why Pydantic Over Manual Parsing

Hand-written validation (`if "risk_score" in data and isinstance(...)`)
is easy to get wrong and easy to forget to update when the schema changes.
It tends to validate presence and type but not range, format, or the
absence of extra fields — exactly the gaps this attack exploits. Pydantic
makes the schema the single source of truth: it's declarative, it fails
loudly with a specific error instead of a downstream `KeyError` or
`TypeError`, and `extra="forbid"` + `strict=True` close the two holes
(unknown fields, coerced types) that manual `dict.get()` parsing almost
always leaves open. The schema is also the contract — anyone reading
`DeviceComplianceReport` knows exactly what the LLM is allowed to hand
back, without reading the parsing logic.

## Run It

```bash
python LLM02-insecure-output-handling/vulnerable.py
python LLM02-insecure-output-handling/mitigated.py
```

`vulnerable.py` may write `PWNED_BY_LLM02.txt` next to itself if the live
model follows the injected formatting instruction — proof of code
execution. `mitigated.py` runs the same payload and blocks it before it
ever reaches `eval()`, because it never calls `eval()` at all.
