# Hackbot Kit

My authorized bounty / lab agent. You type a prompt. I think, use tools, edit
files, and answer. Scope first. Evidence redacted. Active traffic and every file
change need your approve. That's the deal.

Default brain is always **offline** (my own rules + tools, no key, no model).
Models are opt-in. I never auto-switch just because you have a key lying around.
You pick with `/provider` when you want one.

## What this thing actually is

- **Offline** plans tool calls from normal language. Good enough for a lot of hunt work.
- **OpenAI / Claude / etc.** optional brains on the same rails (SCOPE + approve).
- **Cursor** or **Codex** if you're already paying for those plans.
- Hunt loop (`/hunt`) that maps surface, chains probes, writes FINDINGS.
- **Elite is global:** workflows, coverage, SPA/DOM probes, and extreme study notes ship inside the normal packs (`auto`). `advanced` / `study-extreme` are aliases for the full kit — they do not lock you into a subset. See [AGENTS.md](AGENTS.md) + [docs/WORKFLOW_HARNESS.md](docs/WORKFLOW_HARNESS.md).
- PATH toys (httpx, katana, nuclei, ffuf), Playwright, Burp, HexStrike if you bother to set them up.

Your real program junk lives under `targets/<name>/`. Don't commit secrets. Demo
target ships so you can poke something without a program.

## Install

Windows:

```powershell
cd C:\hackbot\hackbot-kit
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
playwright install chromium
```

Linux:

```bash
cd ~/whatever/ophackbot
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
playwright install chromium
# libs missing? playwright install-deps chromium
```

More notes: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md) ·
[docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md).

Then:

```bash
python -m hackbot demo    # fake target + dry-run smoke
python -m hackbot         # REPL (headless / SSH)
python -m hackbot tui     # fullscreen Textual UI (hackbot brand + /commands)
```

### Visual CLI — `hackbot tui`

The good visual is **our** Textual TUI (Toad-like layout, **hackbot** branding and
`/models` `/target` `/yolo` …). Slash commands are handled locally — they never
go to the model as a “hunt step”.

```bash
cd ~/testhackbot/ophackbot
source .venv/bin/activate
pip install -U -e '.[tui]'
export HACKBOT_PROVIDER=codex
python -m hackbot tui
```

Plain REPL stays for thin SSH. Optional external host: [docs/TOAD.md](docs/TOAD.md)
(`toad acp` + `hackbot acp`) — that UI still says “Toad”; prefer `hackbot tui`
if you want only our brand. `hackbot ui` (browser) is deprecated.

**Copy in the TUI:** click a message, or `F2` / `Ctrl+Y` / `/copy`.
**Paste:** multiline composer — Ctrl+V keeps every line; send with `Ctrl+Enter`
(or `/paste`). **Scroll:** wheel + scrollbar + PgUp/PgDn always on.

## Brains

I always boot **offline**. Keys alone do nothing. You have to say `/provider …`
(or set `HACKBOT_PROVIDER` for that shell only).

| Brain | How |
| --- | --- |
| offline | Just open it. No key. |
| openai / anthropic / deepseek / glm / openrouter | Set the key, then `/provider <name>` |
| ollama / lmstudio | Point `HACKBOT_BASE_URL` at local, `/provider ollama` |
| cursor | `pip install 'hackbot-kit[cursor]'`, set `CURSOR_API_KEY`, `/provider cursor` |
| codex | Install Codex CLI, run `codex login` (ChatGPT plan), `/provider codex` |

Windows keys (reopen the terminal after `setx`):

```powershell
setx OPENAI_API_KEY "sk-..."
setx CURSOR_API_KEY "cursor_..."   # Cursor Dashboard → Integrations / API Keys
# Codex: no API key. Just `codex login`.
```

Linux:

```bash
export OPENAI_API_KEY="sk-..."
export CURSOR_API_KEY="cursor_..."
# stick it in ~/.zshrc if you're lazy like me
```

Optional:

```bash
export HACKBOT_MODEL="o4-mini"       # cursor: composer-2.5 / grok-4.5 / …
export HACKBOT_EFFORT="auto"         # auto | minimal | low | medium | high | xhigh
```

`auto` = cheap chat, medium on hunt prompts. In the REPL: `/providers`, `/models`,
`/model`, `/effort`, `/status`, `/tools`.

### Cursor / Codex / offline in plain English

- **Offline**: no bill. Fine for a lot of work.
- **Cursor**: drives my tools as CustomTools (packs: usually core+recon+inject+report
  when you say hunt/vuln stuff). Having httpx on PATH ≠ Cursor will call it. Check
  `/tools`. Long `y/n` waits can kill the Cursor bridge; answer faster or `/clear`
  and retry.
- **Codex**: your ChatGPT plan via `codex exec`. File edits still go through my
  approve panel (`/codex-write` toggles that).

## First five minutes

```text
python -m hackbot
/tools                 # what's actually installed / up
/target demo
check if example.com is in scope
dry-run httpx on example.com for the demo target
```

Just talk. Slash commands are optional shortcuts.

```text
credentials are in Downloads/tokens.yaml
hunt whatever you can on example.com approve
read the image Desktop/scope.png
```

### That yellow "Pass --approve to execute" box

**Don't type anything.** It's a dry-run notice. No traffic went out.

When I actually need you:

```text
permission needed
Allow this action? y/n (n):
```

Then type `y` or `n` (or `approve` / `deny`). That's the real gate.

`/hunt … --approve` (or saying "approve" in NL) unlocks live traffic for that
hunt loop. Without `/force`, OUT_OF_SCOPE stays blocked. `/force on` overrides
**all** SCOPE gates (including OOS) — risk is yours. It never skips approve
unless `/yolo on`.

## Hunt

```text
/target myprogram
/session set A --bearer <tokenA>
/session set B --bearer <tokenB>
/hunt explore this host --approve
```

Or NL:

```text
credentials are in Downloads/tokens.yaml
hunt whatever you can on example.com approve
```

Loop: map surface → pick work → run specialists → validate → FINDINGS.
State under `targets/<name>/hunt/`. Paused on SSO? Capture the session, then:

```text
resume hunt
```

SSO/IdP/MFA: I will **not** type IdP passwords or bypass MFA. Use headed
`browser_capture_session` (you finish login in the browser). Then resume.

No accounts yet? Unauth recon still works: `run_tool` httpx/katana/nuclei,
`analyze_js`, cors/redirect probes, wayback. Approve when you want live hits.

Handy slash stuff:

```text
/target <name> | clear
/force on|off
/hunt <prompt> [--approve] [--budget N]
/hunt status | stop
/session set A --bearer <token>
/status
/tools
/config
/stream on|off
/verbose on|off
/clear  /help  /exit
```

Packs: `HACKBOT_TOOL_PACK=auto|all|core,recon,inject,browser,mobile,report`.

## "How do I ask for X?"

| You say roughly | Tool |
| --- | --- |
| HAR / Burp XML in this file | `import_har` / `import_burp_xml` |
| OpenAPI / Swagger JSON or YAML | `import_openapi` |
| Postman Collection v2 JSON | `import_postman` |
| AI / LLM / RAG / MCP chat endpoint | `llm_prompt_probe`, `llm_rag_probe`, `mcp_agent_probe`, `ai_eval_run` |
| API authz matrix / mass-assign canaries | `api_authz_matrix`, `api_mass_assignment_probe`, … |
| Look at this JS bundle | `analyze_js` |
| Subdomains / wayback | `crt_subdomains` / `wayback_urls` |
| Run httpx / katana / nuclei / ffuf | `run_tool` (dry-run first) |
| IDOR with A/B | `idor_probe` |
| Find login / SSO | `detect_login`, `session_smoke`, `browser_capture_session` |
| Map / extract page | `map_surface`, `extract_page` |
| Draft a report | `write_report_draft` |
| What's up on this box? | `/tools` or `capabilities` |

Bigger table + env knobs (OOB, Burp, Interactsh): [docs/CLI.md](docs/CLI.md).

### API upgrade (OpenAPI / Postman)

```text
import_openapi path=./swagger.yaml base_url=https://api.example.com
import_postman path=./collection.json
# A/B need secrets/sessions.yaml first — matrix asserts + caches labels for assert_diff
api_authz_matrix url=https://api.example.com/users/1 session_a=A session_b=B
curl_request url=https://api.example.com/users/1 session=A   # scoped curl
api_mass_assignment_probe url=https://api.example.com/me
```

OpenAPI/Postman seed `HuntMemory` with method, URL, params, body templates, auth flags,
tags, and risk scores. Ranking prefers authz/BOLA/business-logic paths over static assets;
coverage cells track method × path × param × authz.

### AI / LLM target hunting

Payloads are **offensive but canary-only** (`HB_CANARY_*`). Active AI tools default to
dry-run. Stop on cross-tenant data, real tool execution, or SCOPE prohibitions.
See `bounty_knowledge/study_notes/ai-security/hackbot-ai-hunting.md`.

```text
ai_surface_upsert chat_url=https://chat.example.com/v1/chat prompt_field=messages mcp_urls=https://chat.example.com/mcp
ai_surface_list
llm_prompt_probe url=https://chat.example.com/v1/chat session=A
llm_rag_probe url=https://chat.example.com/v1/chat
mcp_agent_probe url=https://mcp.example.com/rpc
ai_eval_run url=https://chat.example.com/v1/chat families=prompt-injection,rag,tool-abuse
```

## Safety (the short version)

- Every program needs `targets/<name>/SCOPE.md`
- Without `/force`, OUT_OF_SCOPE stays blocked; with `/force` / `/yolo`, operator owns OOS too
- Exact hosts in `in_scope` beat wildcards like `*.example.com` in OOS
- Soft/hard SCOPE gates need `/force` **and** approve (unless `/yolo on`)
- Redirects get re-checked (HTTP and Playwright); force applies per hop
- `prohibited` in SCOPE is real unless `/force` (e.g. heavy automated scanning)
- Secrets get redacted; crank it with `HACKBOT_STRICT_REDACT=1` if you want
- Approvals land in local `audit.log` (gitignored)

Read [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) before you point this at a real
program. Copy `configs/hackbot.example.yaml` → `configs/hackbot.yaml` if you care
about RPS / timeouts (`/config` to peek).

## YOLO + lab (AI runs the box)

Want the brain to keep hunting without `y/n`, and to fix PATH / start Burp itself?

```bash
mkdir -p .hackbot
echo 'your-sudo-password' > .hackbot/sudo_pass
chmod 600 .hackbot/sudo_pass
# or: export HACKBOT_SUDO_PASS='...'
```

In the REPL:

```text
/yolo on
/tools
# AI can call: stack_prepare, burp_ensure, lab_exec
inicie o hunting
```

`/yolo on` skips approve prompts and turns force on (including OOS). Password
never goes in git (`.hackbot/` is ignored). Step mode still pauses after each
hunt act (`HACKBOT_STEP_MODE=0` for the old full-budget loop).

## HexStrike and friends

`/tools` shows what's on PATH and whether HexStrike/Burp answer on localhost.
HexStrike is optional and **not** the kit venv:

```bash
# Docker is the sane path (see integrations/hexstrike/PROVENANCE.md)
cd integrations/hexstrike && docker compose up -d --build

# or its own venv, then:
python -m hackbot run targets/demo --tool hexstrike --approve
curl -sS http://127.0.0.1:8888/health
```

## Layout

```text
hackbot/            agent, tools, hunt, providers
targets/            per-program work (demo ships; yours stay local)
bounty_knowledge/   study notes
integrations/       HexStrike (vendored, loopback only)
docs/               safety, install, CLI reference
configs/            example yaml
```

## Lockfile / scripting

Pins live in `requirements.lock`. Low-level commands (`scope-check`,
`run --tool httpx`, playbooks, …) are in [docs/CLI.md](docs/CLI.md) if you want
to script instead of chat.
