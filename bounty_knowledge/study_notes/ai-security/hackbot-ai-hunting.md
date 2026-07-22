# Hackbot AI / LLM / RAG / MCP hunting

## What

First-class AI target hunting inside Hackbot: prompt injection, indirect injection, RAG leakage, tool-use abuse, MCP exposure, tenant isolation, and system-boundary signals.

## Safe payload philosophy

- Payloads are **offensive in intent** but use **canaries / placeholders only** (`HB_CANARY_*`).
- Never ask the model to dump live secrets, cookies, or production keys into evidence.
- Active tools default to **dry-run** (`approve=false`). YOLO may auto-approve in-scope actions but must still use Hackbot tools.
- HTTP(S) to the target goes only through Hackbot tools (`http_request`, `llm_*`, `mcp_agent_probe`, …).

## Tools

| Tool | Purpose |
|------|---------|
| `llm_prompt_probe` | Direct prompt injection canaries |
| `llm_indirect_prompt_probe` | Untrusted content / indirect injection |
| `llm_rag_probe` | Cross-tenant RAG source signals |
| `llm_tool_abuse_probe` | Excessive agency / tool boundary |
| `llm_tenant_isolation_probe` | Other-object canary → DENIED |
| `mcp_agent_probe` | `tools/list` / `resources/list` |
| `ai_eval_run` | Capped multi-family eval |

## Outcomes → severity

| Outcome | Typical severity |
|---------|------------------|
| `blocked` | Info |
| `canary_returned` | Low–Medium |
| `system_boundary_signal` | Low / Info |
| `tool_attempted` | Medium |
| `tool_executed` | High (depends on action) |
| `cross_tenant_signal` | High |

## When to stop

- Cross-tenant private content appears (redact, record, stop).
- A tool actually executes a privileged action outside dry-run intent.
- SCOPE prohibits AI/automated testing of that surface.
- Smuggling/cache/desync style impact appears — detection only; stop if prohibited.

## Playbooks

`prompt-injection`, `indirect-prompt`, `rag`, `agentic`, `mcp`, `tenant-isolation-ai`, `system-boundary`.
