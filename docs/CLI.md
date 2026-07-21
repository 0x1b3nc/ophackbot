# Hackbot CLI

## Agent mode (default)

This is how I actually use it. You type a task, I read it, think, run tools, and
answer. Same idea as Claude Code or Codex. hackbot is the knowledge and safety
layer, you bring the model.

```powershell
# open once, stays open (what I do)
.\hackbot.cmd
# or
.\.venv\Scripts\python.exe -m hackbot

# one-shot
.\.venv\Scripts\python.exe -m hackbot check if example.com is in scope for targets/demo
```

### Brains

There are four. hackbot **always starts offline** unless I explicitly pin a
provider (`/provider` or `HACKBOT_PROVIDER` in that shell). Keys alone do not
switch the brain.

- offline: no model. Rule-based planner + tools. Home base and the default.
- model: any HTTP provider (OpenAI, Anthropic, DeepSeek, GLM, OpenRouter, or a
  local model). Same tool loop for all of them.
- codex: optional ChatGPT-plan path via `codex exec` (same opt-in as the others).
- cursor: optional Cursor-plan path via `cursor-sdk` local Agent (`CURSOR_API_KEY`).
  With `HACKBOT_CURSOR_TOOLS=1` (default), phase-filtered hackbot tools are registered
  as SDK **CustomTools** so Cursor drives `http_request` / probes / `run_hunt` under
  the same SCOPE / approve / caps rails as the HTTP agent. Mode defaults to `agent`
  when tools are on (`HACKBOT_CURSOR_MODE=plan|agent` to override). Fileop JSON remains
  a fallback. Models are validated (`/models`, `/model grok-4.5|composer-2.5|auto`).
  Effort + fast: `/effort high fast` or `/fast on`. Each turn prints `used model …`.

### Providers

Set a key (optional), then pick in the REPL with `/provider <name>`. Prefer that
over a permanent `setx HACKBOT_PROVIDER` so offline stays the default next open.

```powershell
setx OPENAI_API_KEY "sk-..."          # then in REPL: /provider openai
setx ANTHROPIC_API_KEY "sk-..."       # /provider anthropic
setx DEEPSEEK_API_KEY "sk-..."        # /provider deepseek
setx GLM_API_KEY "..."                # /provider glm
setx OPENROUTER_API_KEY "sk-or-..."   # /provider openrouter
setx HACKBOT_BASE_URL "http://localhost:11434/v1"   # /provider ollama

# Optional Cursor SDK (Cursor plan):
#   pip install 'hackbot-kit[cursor]'   # or: pip install cursor-sdk
#   setx CURSOR_API_KEY "cursor_..."    # Dashboard → Integrations / API Keys
#   /provider cursor
#   /model composer-2.5

# Optional Codex (ChatGPT plan) — not preferred over the others:
#   codex login
#   /provider codex
```

Pin for one shell only if you want: `$env:HACKBOT_PROVIDER="openai"`.
Legacy alias: `HACKBOT_BACKEND` (same values). Clear both if the REPL keeps
opening on Codex/another model:
`[Environment]::SetEnvironmentVariable("HACKBOT_BACKEND",$null,"User")` (and
`HACKBOT_PROVIDER` the same way), then open a new terminal.
Known names: openai, anthropic, codex, cursor, deepseek, glm, openrouter, ollama,
lmstudio, custom, offline.

### Model and reasoning effort

`/model` is **strict for every provider**: only real catalog ids (curated in
the kit + live `/models` from the API/server when available — OpenAI-wire,
OpenRouter, Ollama tags, LM Studio, Anthropic `GET /v1/models`, Cursor catalog).
Live lists are TTL-cached (memory + `.hackbot/model_cache/`); refresh with
`/models refresh`. Garbage strings are rejected. List with `/models`.

```powershell
setx HACKBOT_MODEL "o4-mini"          # must be a real id for that provider
setx HACKBOT_EFFORT "auto"            # auto | minimal | low | medium | high | xhigh
```

`auto` (the default) uses **minimal** for chat (hi/olá/thanks) and **medium**
for hunt tasks. Explicit levels still work. Effort maps to whatever knob each
provider uses: OpenAI and Codex `reasoning_effort`, Anthropic thinking budget,
OpenRouter `reasoning.effort`, GLM thinking. Providers that don't have one just
ignore it.

Chat prompts skip tools and use a short system prompt so a hello stays fast.
Hunt prompts get the full tool pack. Ctrl+C cancels a running turn.
`/verbose on` shows full tool panels; off (default) is one line per tool.

Reopen the terminal after `setx` so it picks up the value.

### Live reasoning (streaming)

I stream my thinking as it happens, then the answer. It's append only so it just
scrolls, no flicker. Turn it off if you want quiet output.

```text
/stream on
/stream off
```

### Editing files

I can create, edit, append, move, delete files, and make directories. Anywhere,
not only inside this repo (Downloads, Desktop, wherever). Before every single
change I show an approval panel with the path and a preview. Approve and I do it,
deny and I drop it.

On the codex brain it works a bit differently under the hood. Codex runs read
only, so it can't touch files itself. Instead it proposes each change and hackbot
applies it through the same approval gate. That's on by default. Flip it with:

```text
/codex-write          toggle codex file changes (on by default, still asks per edit)
```

### REPL commands

```text
/providers            list providers and which ones have a key
/provider <name>      switch provider (also /codex, /local)
/models               model suggestions for the current provider
/model <name>         set the model
/effort <level>       minimal, low, medium, high, xhigh
/stream on|off        live reasoning
/codex-write          toggle codex file changes
/status               show brain, provider, model, effort
/clear   /help   /exit
```

Active traffic (real requests to a target) and every file change still ask before
they happen. That part never gets skipped. Approvals also land in `audit.log`
(gitignored) at the kit root.

### Strict redaction

Regex redact is best effort. Turn on a harder gate when saving evidence or
report drafts:

```powershell
setx HACKBOT_STRICT_REDACT "1"
```

When on, save refuses if the text still looks sensitive or has headers with
values that are not on a small allowlist (custom stuff like
`X-Internal-Session: ...` fails closed).

### SCOPE.md

Prefer a YAML front-matter block at the top of `SCOPE.md` for `in_scope`,
`out_of_scope`, `allowed`, `prohibited`. That is the source of truth. Markdown
below is for notes. Old Markdown-only scopes still work as a fallback.

URL-shaped `in_scope` entries are honored when present: scheme, port, and path
prefix (e.g. `https://api.example.com:8443/v1/*`). Bare hostnames still mean
any scheme/port/path on that host. CIDR / IP entries work too (`10.0.0.0/8`,
`2001:db8::/32`). `prohibited` is enforced (force can soft-override; explicit
OOS stays hard). Aggression prefers tool id over free text. Browser traffic
(Playwright) re-gates every request/redirect the same way HTTP does.

### Config (`configs/hackbot.yaml`)

Copy [configs/hackbot.example.yaml](../configs/hackbot.example.yaml) to
`configs/hackbot.yaml`. Effective knobs today:

- `safety.default_max_rps` (or `HACKBOT_MAX_RPS`) — caps `rate_probe` concurrency
- `safety.subprocess_timeout_sec` (or `HACKBOT_SUBPROCESS_TIMEOUT`) — external tool timeout

OOS hard-block, required `SCOPE.md`, and approve for active/destructive work stay
on even if the YAML tries to turn them off.

Import a program policy dump into YAML:

```powershell
.\.venv\Scripts\python.exe -m hackbot policy-import targets/demo --file policy.md --write
```

### Hunt mode

```text
/target demo          load SCOPE + RESUME + FINDINGS into the session
/target clear
/force on             soft SCOPE override (level-3 / NOT_CONFIRMED); OOS still blocked
/force off
/status               shows brain + active target + force + next step
/config               effective safety knobs (max RPS, subprocess timeout, …)
/hunt <prompt> [--approve] [--budget N]   autonomous OODA hunter
/hunt status
/hunt stop
```

`/force` is **operator responsibility**: it does not skip approve, and it cannot
unlock explicitly OUT_OF_SCOPE hosts. Soft gates (missing level-3 / active
wording, NOT_CONFIRMED hosts) can be overridden. Redirects and HAR/OpenAPI-derived
fetches re-check the **effective destination** each hop. See [SAFETY_MODEL.md](SAFETY_MODEL.md).

**Natural language first.** You do **not** need `/hunt` or `/session`. Just talk:

```text
as credenciais estão no arquivo tokens.yaml em Downloads; depois explora o que der em example.com approve
leia a imagem Desktop/scope.png e resume o que está in-scope
explora vulnerabilidades em example.com
```

Slash commands below are optional shortcuts.

### Autonomous hunt (`/hunt` shortcut)

This is the main path to finish a bounty-style engagement without naming tools:

```text
/target demo
/session set A --bearer <tokenA>
/session set B --bearer <tokenB>
/hunt explora o que der nesse host --approve
```

One **session approve** unlocks active traffic for the whole loop (map surface →
prioritize → specialists with chaining → validate → FINDINGS). OOS stays
hard-blocked. Without `--approve`, the loop dry-runs / plans only.

State lives under `targets/<name>/hunt/` (`surface.yaml`, `attempts.jsonl`,
`candidates.yaml`, `state.yaml`). Budget default ~28 (`HACKBOT_HUNT_BUDGET`).
Acts are split across phases **recon → authz → inject**
(`HACKBOT_HUNT_PHASE_BUDGETS=recon:30,authz:35,inject:35`). Clean streaks ban
a module and **pivot** to siblings. Validate replays the winning act (not just
GET) and correlates Interactsh/OOB when a canary exists. Authz defaults to a
BOLA/BFLA write matrix (`GET,PATCH,PUT,DELETE` / GraphQL mutation) when A/B
ready. Findings auto-draft Bugcrowd/VRT submit-ready reports
(`HACKBOT_REPORT_PLATFORM=bugcrowd`). Learning stores param/payload hints for
the next host.

Vague offline prompts (“explora o que der…”) also plan `run_hunt` instead of
the older linear campaign pack.

### Authz hunting (A/B sessions)

Prefer NL — point at a file:

```text
as sessões A/B estão em targets/demo/secrets/sessions.yaml
# or
credenciais no arquivo C:\Users\you\Downloads\tokens.json
```

That calls `load_sessions_from_file` (asks once to write into gitignored
`secrets/sessions.yaml`). Optional shortcut:

```text
/target demo
/session set A --bearer <tokenA>
/session set B --bearer <tokenB>
/sessions
```

### Images / screenshots

```text
leia a imagem Downloads/burp-idor.png e me diga o endpoint
```

Uses `read_image` (tesseract OCR if installed; optional vision via
`HACKBOT_VISION=1` + model). Paths under kit, home, Downloads/Desktop are readable.

### Essential bounty tools (NL)

| Ask in natural language | Tool |
| --- | --- |
| HAR / Burp export in file X | `import_har` |
| Analyze `app.js` / bundle URL | `analyze_js` |
| Decode this JWT | `analyze_jwt` |
| GraphQL introspection | `graphql_probe` |
| CORS / open redirect | `cors_probe` / `open_redirect_probe` |
| Hidden params | `mine_params` |
| LFI / SSTI / XXE | `lfi_probe` / `ssti_probe` / `xxe_probe` |
| JWT active (alg=none / claim flip) | `jwt_active_probe` |
| OAuth authorize checks | `oauth_probe` |
| Exploit chains A→B | `build_chains` |
| Subdomains / wayback | `crt_subdomains` / `wayback_urls` |
| Security headers | `analyze_headers` |
| What’s in folder X | `list_dir` |
| Open page / screenshot (Playwright) | `browser_navigate` / `browser_screenshot` |
| Cookies / web storage (redacted) | `browser_cookies` / `browser_storage` |
| Capture XHR during load → surface | `browser_network` |
| Open as session A/B (inject auth) | `browser_with_session` |
| Diff same URL as A vs B (soft IDOR) | `browser_diff_sessions` |
| Burp XML → surface | `import_burp_xml` |
| Local Burp REST up? | `burp_rest_health` |
| What worked before? | `learn_suggest` |
| Mobile toolchain / adb / APK peek | `mobile_status` / `adb_devices` / `inspect_apk` |
| APK + HAR → surface (+ hunt) | `mobile_bridge` |
| Draft bounty report (any portal) | `write_report_draft` (`generic` default) |
| SSRF / race / websocket | `ssrf_probe` / `race_probe` / `websocket_probe` |
| IDOR A/B systematic | `idor_probe` (GET + capped PATCH/PUT write matrix) |
| Session bootstrap | `session_bootstrap` + `secrets/accounts.yaml` |
| Content discovery (capped) | `discover_paths` (soft-404 baseline) |
| OOB / Interactsh | `oob_mint` / `interactsh_*` (`HACKBOT_OOB_BASE`) |
| Cookie jar across acts | `http_request` → `secrets/cookie_jar.json` |
| Hunt checklist / pause | `hunt_checklist` / `hunt_pause` / `hunt_telemetry` |
| Burp REST history/issues | `burp_proxy_history` / `burp_issue_list` |
| CDP local probe | `cdp_attach` |
| MobSF health/upload/scan | `mobsf_health` / `mobsf_upload` / `mobsf_scan` |
| Frida/Objection (approve + allowlist) | `frida_status` / `frida_run_script` / `objection_explore` |
| Console / set cookie (Playwright) | `browser_console` / `browser_set_cookie` |
| Learning stats | `learn_stats` |

### Demo pitch smoke

```powershell
.\.venv\Scripts\python.exe -m hackbot demo
# or: python -m hackbot.demo
```

Prepares `targets/demo` (SCOPE + fake A/B sessions) and dry-runs the main loop.

Tool packs (fewer tools to the model): `HACKBOT_TOOL_PACK=auto|all|core,recon,inject,browser,mobile,report`.

Playwright is a **default** dependency (`pip install -e .`). Chromium: `playwright install chromium`.
Frida scripts are allowlisted lab templates only — never silent hooks.

Optional browser install: `pip install 'hackbot-kit[browser]'` then `playwright install chromium`.

Frida hooks are **not** auto-run (operator-driven). Use `inspect_apk` / `mobile_bridge` + Burp HAR for mobile APIs.

Autonomous `run_hunt` already chains content discovery, headers, CORS, params,
GraphQL, redirect, LFI/SSTI/SSRF (with OOB when `HACKBOT_OOB_BASE` is set), and
systematic `idor_probe` A/B when sessions are loaded — then `build_chains` and
learning ingest. Cookie jar persists under `secrets/cookie_jar.json`.

OOB / Interactsh (blind SSRF/XSS/XXE):

```powershell
# Real Interactsh client (register + encrypted poll) — preferred
setx HACKBOT_INTERACTSH "1"
# optional: setx HACKBOT_INTERACTSH_SERVER "oast.pro"
# optional auth: setx HACKBOT_INTERACTSH_TOKEN "..."
pip install cryptography

# Legacy Collaborator-style base + poll URL
setx HACKBOT_OOB_BASE "https://YOUR.oast.fun"
setx HACKBOT_OOB_POLL_URL "https://YOUR/poll?id=TOKEN"
setx HACKBOT_OOB_AUTH "Bearer ..."
```

SSRF / XSS / XXE probes auto-mint + poll when OOB is configured. Without env,
canaries stay local reflection markers only.

Burp control plane (local only):

```powershell
setx HACKBOT_BURP_BASE "http://127.0.0.1:1337"
# optional API key / MCP stdio bridge
setx HACKBOT_BURP_API_KEY "..."
setx HACKBOT_BURP_MCP_CMD "path\to\burp-mcp-server.exe"
```

NL: `burp replay https://example.com/api` → `burp_replay` (dry-run until approve).
If REST/MCP is down, replay falls back to scoped `http_request`.

### Report drafts (any bounty platform)

```text
monta o draft do report a partir do FINDINGS
draft yeswehack do C-001
write-up bugcrowd
```

Default is **`generic`** — a portable markdown you paste into Bugcrowd, HackerOne,
Intigriti, YesWeHack, Synack, Immunefi, etc. Named platforms only tweak headings
(VRT / weakness / …). Drafts include **severity + CVSS hints** from bug class
(triage aids — confirm against program policy). Output:
`targets/<name>/reports/<platform>_draft.md`.

`browser_diff_sessions` with a soft IDOR hint **auto-promotes** a hunt candidate and
runs the validator (`verdict=likely` → FINDINGS). Pass `promote=false` to skip.

### Manual IDOR playbook

### Campaign (named multi-attack + results)

When you **name** classes (DDoS, bruteforce, secrets, …), offline still uses
`run_campaign`. Open-ended prompts prefer `/hunt` / `run_hunt`.

Talk like this (offline or model) — **PT-BR or English**:

```text
/target demo
/force on
de acordo com o scope, faça DDoS, bruteforce, bypass de senha, achar tokens
privados e leak de credenciais em example.com approve
```

FOUND rows are promoted through the **validator** into `FINDINGS.md` (proof
required). Vague prompts without named classes use autonomous hunt instead.
If offline confidence is low and a model is configured (`/provider`), Hackbot
asks the model to interpret the prompt (JSON router) then executes with the
same SCOPE/approve/force rails. Disable with `HACKBOT_AUTO_ROUTE=0`.
Threshold: `HACKBOT_ROUTE_THRESHOLD=0.68`.

Open a class playbook (falsifiable steps, not just notes):

```powershell
.\.venv\Scripts\python.exe -m hackbot playbook idor --endpoint https://example.com/api/orders/1
# dry-run executable steps
.\.venv\Scripts\python.exe -m hackbot playbook rate-limit --run --host example.com --target-dir targets/demo
# bounded rate probe (dry-run)
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool rate_probe --host example.com
```

In the agent: `open_playbook` / `run_playbook` / `set_target` tools do the same thing.
Offline brain: `attack` / `test for` / `hunt` → `run_playbook` (dry-run unless you say approve).

### HexStrike containment

Prefer Docker (host loopback only, no `targets/` mount):

```powershell
cd integrations\hexstrike
docker compose up -d --build
# or
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool hexstrike --docker --approve
```

See `integrations/hexstrike/PROVENANCE.md`.

## Low-level commands (optional)

Still here if you want to script things:

```powershell
.\.venv\Scripts\python.exe -m hackbot cmd
.\.venv\Scripts\python.exe -m hackbot scope-check targets/demo --host example.com
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool httpx --host example.com
```
