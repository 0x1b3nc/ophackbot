# AGENTS.md — Hackbot operator contract

Hard rules (never weaken):

1. **SCOPE.md is law** — OUT_OF_SCOPE traffic is blocked; `/force` cannot override OOS.
2. **Dry-run default** — traffic tools use `approve=false` unless the operator approves ACTIVE.
3. **Redaction** — evidence goes through redaction; no secrets in git.
4. **STEP_MODE mindset** — one significant action per turn when step mode is on: hypothesis → tool → evidence → stop → next suggestion.
5. **No DoS / destruction** — smuggle/cache probes are detection-only; prohibited playbook = identify + stop.

## Packs

Elite tools and extreme study notes are **global** — folded into normal packs.

| Pack | Role |
|------|------|
| `core` | session, scope, hunt, **open_knowledge** (incl. extreme), workflows, coverage |
| `recon` / `inject` / `browser` / `mobile` / `report` | phase tools **including** elite probes / SPA / proxy |
| `advanced` / `study-extreme` | **aliases for `all`** — never strip the kit to “study only” |

Default `HACKBOT_TOOL_PACK=auto` already exposes study + elite with the usual phase filter. Use `all` when you want every tool every turn.

## Workflows

- YAML: `targets/<name>/hunt/workflows/<id>.yaml`
- Tools: `workflow_load` → `workflow_run` (dry) → approve ACTIVE → `workflow_assert` / `coverage_map`
- Design: [docs/WORKFLOW_HARNESS.md](docs/WORKFLOW_HARNESS.md)

## Hunt loop expectations

Each agent step should state:

`hypothesis | endpoint | aggression 0-3 | policy quote | tool | expected evidence | stop | cleanup`

Prefer authz / business-logic over generic reflected XSS. Use `hunt_cockpit` for summary.

## API + AI packs

- Ingest: `import_openapi`, `import_postman` → HuntMemory + coverage cells.
- API probes: `api_authz_matrix`, `api_*` canary probes (dry-run default).
- AI probes: `llm_prompt_probe`, `llm_rag_probe`, `mcp_agent_probe`, `ai_eval_run`.
- Playbooks: `prompt-injection`, `rag`, `agentic`, `mcp`, `system-boundary`, …
- Knowledge keywords: `llm`, `rag`, `mcp`, `prompt-injection`, `agentic`.
- AI payloads are canary-only (`HB_CANARY_*`); stop on cross-tenant data or real tool execution.

## Extreme study

`open_knowledge` task keywords: `extreme`, `business-logic`, `saml`, `smuggle`, `prohibited`, `llm`, `rag`, `mcp`, …

Playbooks: `invite-idor`, `dom-xss`, `cache-detect`, `prohibited-stop`.
