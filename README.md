# Hackbot Kit

Authorized bounty / lab agent. You type a task; hackbot plans, uses tools, edits
files, and answers. **SCOPE first.** Evidence is redacted. Active traffic and
every file change need your **approve**.

hackbot is the knowledge + safety layer. Models are optional. The default brain
is always **offline** (rule-based planner + tools — no API key). Plug in a model
only when you want one. It never auto-switches; you pick with `/provider`.

## What you get

| Layer | Role |
| --- | --- |
| Offline brain | Default. Plans tools from natural language, no model bill |
| Model / Codex / Cursor | Optional “brain” that can drive the same tools |
| SCOPE + approve | Hard rails: in/out of scope, dry-run vs live traffic |
| Hunt loop | Autonomous OODA (`/hunt` / `run_hunt`) with resume after SSO |
| Integrations | httpx/katana/nuclei/ffuf, Playwright, Burp, HexStrike, OOB |

Private program data stays under `targets/<program>/` (not for public commits).

## Install

**Windows**

```powershell
cd C:\hackbot\hackbot-kit
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
playwright install chromium
```

**Linux**

```bash
cd /path/to/ophackbot   # or hackbot-kit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
playwright install chromium
# if Chromium deps fail: playwright install-deps chromium
```

More detail: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md) ·
[docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md).

Smoke:

```bash
python -m hackbot demo
python -m hackbot   # interactive REPL
```

## Brains (providers)

Always starts **offline** unless you set `/provider` or `HACKBOT_PROVIDER` for
that shell. Having an API key installed does **not** auto-switch the brain.

| Brain | How to enable |
| --- | --- |
| **offline** | Default — no key |
| **openai / anthropic / deepseek / glm / openrouter** | Set key → `/provider <name>` |
| **ollama / lmstudio** | Local OpenAI-compatible URL → `/provider ollama` |
| **cursor** | `pip install 'hackbot-kit[cursor]'` + `CURSOR_API_KEY` → `/provider cursor` |
| **codex** | Install Codex CLI → `codex login` (ChatGPT plan) → `/provider codex` |

**Windows keys**

```powershell
setx OPENAI_API_KEY "sk-..."          # then new terminal: /provider openai
setx ANTHROPIC_API_KEY "sk-..."
setx CURSOR_API_KEY "cursor_..."      # Dashboard → Integrations / API Keys
# Codex: no API key — run `codex login`
```

**Linux keys**

```bash
export OPENAI_API_KEY="sk-..."
export CURSOR_API_KEY="cursor_..."
# persist in ~/.zshrc or ~/.bashrc if you want
```

Model + effort (optional):

```bash
export HACKBOT_MODEL="o4-mini"          # or composer-2.5 / grok-4.5 for cursor
export HACKBOT_EFFORT="auto"            # auto | minimal | low | medium | high | xhigh
```

`auto` = light for chat, medium for hunt tasks. In the REPL: `/providers`,
`/models`, `/model`, `/effort`, `/status`, `/tools`.

### Cursor vs Codex vs offline

- **Cursor** registers phase-filtered hackbot tools as CustomTools
  (`HACKBOT_CURSOR_TOOLS=1`). Packs default to `auto` (core+recon+inject+report
  on hunt prompts). Not every binary runs unless the model calls `run_tool` /
  probes — check `/tools`.
- **Codex** uses your ChatGPT plan via `codex exec`. File edits still go through
  hackbot’s approve gate (`/codex-write` toggles proposals).
- **Offline** is enough for many hunt steps without a paid model.

## First session

```text
python -m hackbot
/tools                          # what binaries + HexStrike/Burp are actually up
/target demo                    # or your program folder under targets/
check if example.com is in scope
dry-run httpx on example.com for the demo target
```

Talk normally — slash commands are shortcuts, not required:

```text
credentials are in Downloads/tokens.yaml
hunt whatever you can on example.com approve
read the image Desktop/scope.png
```

### Approve: dry-run vs live

| What you see | What to do |
| --- | --- |
| Yellow **dry-run** / “Pass --approve to execute” | **Nothing.** Informational only — no traffic was sent |
| **permission needed** → `Allow this action? y/n` | Type **`y`** or **`n`** (also `approve` / `deny`) |
| Normal `hackbot · …:` prompt | New task |

One session `/hunt … --approve` (or NL “approve”) unlocks active traffic for
that hunt loop. OUT_OF_SCOPE stays hard-blocked. `/force` only softens missing
active-testing / NOT_CONFIRMED wording — never OOS, never skips approve.

## Hunt workflow

```text
/target myprogram
/session set A --bearer <tokenA>
/session set B --bearer <tokenB>
/hunt explore this host --approve
```

Or natural language (sessions from a file, then hunt):

```text
credentials are in Downloads/tokens.yaml
hunt whatever you can on example.com approve
```

What happens: map surface → prioritize → specialists (recon/authz/inject) →
validate → `FINDINGS.md`. State under `targets/<name>/hunt/`
(`surface.yaml`, `state.yaml`, …). Resume after pause:

```text
resume hunt
# or: run_hunt with resume=true / HACKBOT_HUNT_RESUME=1
```

**SSO / IdP / MFA:** hackbot never types IdP passwords or bypasses MFA. Use
headed `browser_capture_session` (you finish login in the browser) → session
saved + smoked. Hunt stops on `needs_setup`; capture, then resume.

**Without accounts:** unauth recon still works — `run_tool` httpx/katana/nuclei,
`analyze_js`, `cors_probe`, `open_redirect_probe`, `wayback_urls`, etc. (approve
for live traffic).

### Useful REPL shortcuts

```text
/target <name> | clear
/force on|off
/hunt <prompt> [--approve] [--budget N]
/hunt status | stop
/session set A --bearer <token>
/status          # brain + target + compact stack
/tools           # httpx/katana/nuclei/ffuf + HexStrike/Burp health
/config
/stream on|off
/verbose on|off
/clear  /help  /exit
```

Tool packs: `HACKBOT_TOOL_PACK=auto|all|core,recon,inject,browser,mobile,report`.

## Common asks → tools

| You say | Tool |
| --- | --- |
| HAR / Burp XML in file X | `import_har` / `import_burp_xml` |
| Analyze `app.js` / bundle URL | `analyze_js` |
| Subdomains / wayback | `crt_subdomains` / `wayback_urls` |
| httpx / katana / nuclei / ffuf | `run_tool` (dry-run first) |
| IDOR A/B | `idor_probe` (+ sessions A/B) |
| Detect login / SSO | `detect_login` · `session_smoke` · `browser_capture_session` |
| Map surface / extract page | `map_surface` · `extract_page` |
| Draft bounty report | `write_report_draft` |
| What’s installed / up? | `capabilities` or `/tools` |

Full NL ↔ tool table and env knobs (OOB, Burp REST, Interactsh): see
[docs/CLI.md](docs/CLI.md) (reference only).

## Safety (short)

- Every program needs `targets/<name>/SCOPE.md` (YAML front-matter preferred)
- Explicit **OUT_OF_SCOPE** is hard-blocked (even with `/force`)
- Exact `in_scope` hosts win over OOS wildcards like `*.example.com`
- Soft gates (level-3 / NOT_CONFIRMED) need `/force` **and** approve
- HTTP + Playwright re-check every redirect destination
- `prohibited` in SCOPE is enforced (e.g. heavy automated scanning)
- Evidence redacts secrets (optional `HACKBOT_STRICT_REDACT=1`)
- Approvals append to local `audit.log` (gitignored)

Read [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md) and
[docs/OPERATING_RULES.md](docs/OPERATING_RULES.md) before real hunting.

Copy `configs/hackbot.example.yaml` → `configs/hackbot.yaml` for RPS / timeouts
(`/config` to inspect).

## HexStrike / recon CLIs

PATH tools (httpx, katana, nuclei, ffuf) show up in `/tools` when installed.
HexStrike is **optional** and separate from the kit venv:

```bash
# preferred: Docker — see integrations/hexstrike/PROVENANCE.md
cd integrations/hexstrike && docker compose up -d --build

# or local hexstrike venv (not the hackbot .venv), then:
python -m hackbot run targets/demo --tool hexstrike --approve
curl -sS http://127.0.0.1:8888/health
```

## Layout

```text
hackbot/            # agent, tools, hunt, providers
targets/            # per-program workspaces (demo ships; your programs stay local)
bounty_knowledge/   # study notes
integrations/       # HexStrike (vendored, loopback-only)
docs/               # SAFETY_MODEL, OPERATING_RULES, CLI reference, install
configs/            # hackbot.example.yaml
```

## Lockfile & low-level CLI

Runtime pins: `requirements.lock` (from `requirements.in`).

Scripting still works (`scope-check`, `run --tool httpx`, `playbook`, …) —
reference: [docs/CLI.md](docs/CLI.md).
