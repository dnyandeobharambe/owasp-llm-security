# OWASP LLM Top 10 — Implementation Guide

**Most enterprises document OWASP LLM risks. Almost none implement the mitigations.**

This repo shows the implementation — working Python code demonstrating each
OWASP LLM Top 10 risk with a vulnerable example and a production-safe mitigated
example side by side.

Built with **Gemini API**. Framework-agnostic. Runs locally without cloud setup.

---

## Why this repo exists

Microsoft documented MCP security risks.  
OWASP documented LLM risks.  
Nobody wrote the code.

This repo fills that gap — every risk has:
- A **vulnerable implementation** you can run and watch fail
- A **mitigated implementation** with production-safe patterns
- A **README** explaining the attack vector, why it matters in enterprise,
  and the design decisions behind each defense layer

---

## The gap between documentation and implementation

```
OWASP says:          "Implement input validation to prevent prompt injection"
This repo shows:      Pattern library + sanitizer + bounded prompt + LLM Judge
                      — running code, not a checklist
```

```
Microsoft says:       "Use least privilege for MCP tool access"
This repo shows:      Tool contract validation, typed interfaces, audit logging
                      — running code, not a diagram
```

---

## Implementation status

| Risk | Title | Status | Key Pattern |
|------|-------|--------|-------------|
| LLM01 | Prompt Injection | ✅ Complete | Input sanitization + LLM Judge |
| LLM02 | Insecure Output Handling | 🔄 In progress | Output schema validation + Pydantic |
| LLM03 | Training Data Poisoning | 📋 Planned | Data provenance + validation |
| LLM04 | Model DoS | 📋 Planned | Rate limiting + token budgets |
| LLM05 | Supply Chain | 📋 Planned | Dependency verification |
| LLM06 | Sensitive Info Disclosure | 🔄 In progress | Microsoft Presidio PII scrubbing |
| LLM07 | Insecure Plugin Design | 📋 Planned | MCP tool contract validation |
| LLM08 | Excessive Agency | 🔄 In progress | HITL gate in LangGraph |
| LLM09 | Overreliance | 📋 Planned | Confidence scoring + human review |
| LLM10 | Model Theft | 📋 Planned | API security + rate limiting |
| MCP Security | MCP-Specific Risks | 📋 Planned | Confused deputy + token passthrough |

---

## How OWASP LLM risks map to MCP attack surface

MCP (Model Context Protocol) introduces a specific attack surface that
traditional OWASP LLM guidance does not fully address.

| OWASP Risk | MCP Attack Vector | Implementation |
|------------|-------------------|----------------|
| LLM01 — Prompt Injection | Malicious content in MCP tool responses injected into agent context | Tool response sanitization before context insertion |
| LLM06 — Sensitive Info | MCP tool returns PII that leaks into LLM context or logs | Presidio scrubbing on all tool responses |
| LLM07 — Insecure Plugin | MCP tool contracts not validated — agent calls tools with wrong parameters | Typed tool interfaces + contract validation |
| LLM08 — Excessive Agency | Agent calls destructive MCP tools without human approval | HITL gate — suggest and execute as separate nodes |
| Confused Deputy | MCP server tricked into acting on behalf of attacker | OAuth scopes + caller validation per tool |
| Token Passthrough | Agent passes its auth token to MCP tools that shouldn't have it | Scoped tokens per tool, never pass agent token |

---

## Repo structure

```
OWASP26/
├── llm_client.py
├── requirements.txt
├── .env
├── .env.example
├── .gitignore
├── README.md
└── LLM01-prompt-injection/
    ├── vulnerable.py
    ├── mitigated.py
    └── README.md
```

---

## Quick start

```bash
# Clone
git clone https://github.com/dnyandeobharambe/owasp-llm-security
cd owasp-llm-security

# Install
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env — add your GEMINI_API_KEY

# Run LLM01 — watch vulnerable fail, mitigated block
python LLM01-prompt-injection/vulnerable.py
python LLM01-prompt-injection/mitigated.py
```

---

## Design principles applied across all examples

**1. Vulnerable and mitigated side by side**  
Every risk has both implementations. Run the vulnerable one first — see the
attack succeed. Then run the mitigated one — see the defense hold.

**2. LLM Judge independence**  
Where a secondary LLM validates output, it always reads from source — never
from shared context with the primary model. Shared context = rubber stamp.
Independence is what makes the validation real.

**3. Fail closed not fail open**  
When a defense layer fails to parse or validate — block the output.
Never pass through on uncertainty. Security systems that fail open are
not security systems.

**4. Audit everything**  
Every suspicious attempt, every blocked response, every Judge decision is
logged with session ID and timestamp. You cannot audit what you did not log.

**5. Typed interfaces over raw strings**  
Pydantic models for inputs and outputs wherever possible. Type contracts
reduce the attack surface and make violations explicit.

---

## Enterprise context

These patterns are directly applicable to:

- **Agentic AI systems** — agents with tool access to enterprise systems
- **RAG pipelines** — document ingestion from untrusted sources
- **MCP servers** — AI agents connected to ERP, CRM, databases
- **Customer-facing AI** — any LLM exposed to public input

The governance layer in production enterprise AI is not a PowerPoint.
It is running code — HITL gates, LLM Judges, PII scrubbers, audit trails.
This repo shows what that looks like.

---

## Author

**Dnyandeo Bharambe (Danny)** — Principal AI Architect  
Enterprise agentic AI systems | LangGraph · MCP · RAG · LLMOps

- GitHub: [github.com/dnyandeobharambe](https://github.com/dnyandeobharambe)
- Blog: [mcpoverrag.hashnode.dev](https://mcpoverrag.hashnode.dev)
- LinkedIn: [linkedin.com/in/dnyandeo](https://linkedin.com/in/dnyandeo)
- Consulting: [topmate.io/dnyandeobharambe](https://topmate.io/dnyandeobharambe)

---

## Related work

- [Enterprise Agentic Audit Engine](https://github.com/dnyandeobharambe/enterprise-agentic-audit-engine) — LangGraph + MCP + LLM Judge in production
- [Agentic Diet Engine](https://github.com/dnyandeobharambe/agentic-diet-engine) — Advanced RAG with LangSmith observability
- [Microsoft MCP Security Guide](https://github.com/microsoft/mcp-for-beginners/blob/main/02-Security/README.md) — Microsoft's MCP security documentation (this repo implements the patterns)

---

## Contributing

PRs welcome — especially:
- Additional attack payloads for existing risks
- Implementations for planned risks (LLM03-05, 07, 09-10)
- MCP-specific attack demonstrations
- Framework-specific adaptations (LangChain, LlamaIndex)
