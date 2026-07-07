# OWASP LLM Security — Claude Code Context

## What This Repo Is
Working implementations of OWASP LLM Top 10 security risks.
Each risk has: vulnerable.py (attack succeeds) + mitigated.py (defense holds) + README.md

## Philosophy
Same as mcp-security-patterns:
The deterministic layer decides. LLM behavior alone is not a security control.

## Stack
- Python 3.11+
- Gemini Flash (gemini-2.5-flash) via google-generativeai
- Presidio for PII detection (LLM06)
- Pydantic for output validation
- python-dotenv

## Pattern Structure
Each folder:
├── vulnerable.py   — attack succeeds, shows the risk
├── mitigated.py    — defense holds, production-safe pattern
└── README.md       — attack vector, defense design decisions

## Completed
- LLM01 ✅ — Prompt Injection — input sanitization + LLM Judge
- LLM02 ✅ — Insecure Output Handling — output schema validation + Pydantic

## In Progress — Complete These Next
- LLM06 — Sensitive Info Disclosure — Presidio PII scrubbing
- LLM08 — Excessive Agency — HITL gate in LangGraph

## Planned — Build After
- LLM03 — Training Data Poisoning — data provenance + validation
- LLM04 — Model DoS — rate limiting + token budgets
- LLM05 — Supply Chain — dependency verification
- LLM07 — Insecure Plugin Design — MCP tool contract validation
- LLM09 — Overreliance — confidence scoring + human review
- LLM10 — Model Theft — API security + rate limiting

## Domain
Same IoT device fleet management domain as mcp-security-patterns.
Consistent domain makes the risks easier to understand in context.

## Design Principles
1. Vulnerable first — see the attack succeed before the defense
2. LLM Judge independence — never share context with primary model
3. Fail closed — block on uncertainty, never pass through
4. Audit everything — log every blocked attempt with session ID
5. Typed interfaces — Pydantic models over raw strings