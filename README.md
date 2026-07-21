# Hackbot Kit

My authorized bounty / lab agent. You type a prompt. I think out loud (live
streaming), use tools, edit files, and answer. Scope first. Evidence redacted.
Active traffic and every file change need your approve.

It's model-agnostic: the default brain is **offline** (rule based, no key, no
network). Plug in any model when you want more (OpenAI, Claude, DeepSeek, GLM,
OpenRouter, local via Ollama/LM Studio, or your ChatGPT plan through Codex). It
never switches brains on its own. you pick.

## Install

```powershell
cd C:\hackbot\hackbot-kit
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

hackbot is the knowledge + safety layer; you bring the model. Set a key for any
provider and it auto-detects (reopen the terminal after `setx`):

```powershell
setx OPENAI_API_KEY "sk-..."        # OpenAI (paid API)
setx ANTHROPIC_API_KEY "sk-..."     # Claude
setx DEEPSEEK_API_KEY "sk-..."      # DeepSeek
setx OPENROUTER_API_KEY "sk-or-..." # OpenRouter (many models, one key)
setx HACKBOT_BASE_URL "http://localhost:11434/v1"  # Ollama / LM Studio (free, local)
```

No key? Nothing to do. hackbot runs **offline** by default (rule based, still
runs tools). Or use your ChatGPT plan via the Codex CLI (`codex login`, then
`setx HACKBOT_PROVIDER codex`).

Pick model + reasoning effort anytime:

```powershell
setx HACKBOT_MODEL "o4-mini"
setx HACKBOT_EFFORT "auto"   # auto | minimal | low | medium | high | xhigh
```

`auto` keeps chat (hi/olá) on minimal effort with no tools, and hunt tasks on
medium with the full tool pack. In the REPL: `/providers`, `/provider`,
`/model`, `/effort`, `/verbose`, `/status`. See [docs/CLI.md](docs/CLI.md).

Windows notes: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md)  
Linux notes: [docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md)

## Use it

```powershell
# interactive agent (default)
.\.venv\Scripts\python.exe -m hackbot

# demo pitch smoke (SCOPE + fake A/B sessions, dry-run)
.\.venv\Scripts\python.exe -m hackbot demo

# one-shot
.\.venv\Scripts\python.exe -m hackbot check if example.com is in scope for targets/demo
```

Inside the REPL, talk normally:

```text
hackbot: open IDOR notes and draft a plan for https://example.com/api/orders/1 on targets/demo
hackbot: dry-run httpx against example.com for the demo target
hackbot: create a scratch.md in my Downloads with today's plan
```

I can create, edit, append, move, and delete files anywhere, not just this repo.
Every change pops an approval panel with the path and a preview first. Deny it
and I back off. Reasoning streams live as I think (toggle with `/stream`).

## Hunt workflow

```text
as credenciais estão no arquivo tokens.yaml em Downloads
explora o que der em example.com approve
```

Or the short form (slash commands are optional shortcuts):

```text
/target demo
/session set A --bearer <tokenA>
/session set B --bearer <tokenB>
/hunt explora o que der nesse host --approve
```

Natural language loads sessions from files, maps surface, chains specialists,
validates proof, then writes FINDINGS. One `approve` covers active traffic;
OOS stays hard-blocked. State under `targets/<name>/hunt/`.

Screenshots: `leia a imagem Desktop/scope.png` → `read_image` (OCR/vision).

Also first-class: HAR/Burp XML import, Playwright navigate/screenshot/cookies/storage/network
+ session inject / A-vs-B diff, mobile bridge, portable bug-bounty report drafts (any portal),
JS/JWT/GraphQL/CORS/redirect/param mining, LFI/SSTI/XXE, crt.sh/wayback, headers, `list_dir`,
and thin cross-program learning — all via normal language.

**Campaign mode:** named classes still use `run_campaign` → FOUND/NOT_FOUND →
validator → FINDINGS. Vague prompts prefer autonomous hunt. Low offline
confidence + `/provider` uses the JSON router (`HACKBOT_AUTO_ROUTE=1`).

## Safety

- Every target needs `SCOPE.md` (YAML front-matter preferred; Markdown fallback)
- Explicitly OUT_OF_SCOPE hosts are hard-blocked (even with `/force`)
- Soft gates (level-3 / NOT_CONFIRMED) yield to `/force` + approve
- `run_tool` / `rate_probe` default to dry-run; approve asks you first
- Level-3 probes are capped (`rate_probe`: concurrency ≤ 20, total ≤ 100)
- Every file change asks approval (path + preview/diff) before it happens
- Writable paths default to kit + home + Downloads/Desktop (see `HACKBOT_WRITE_DIRS`)
- Sensitive paths like `~/.ssh` / `~/.aws` are hard blocked
- Approvals append to local `audit.log` (gitignored) with target/tool/host/`force_override`
- Evidence redacts cookies, tokens, emails, common secrets (regex is best effort;
  set `HACKBOT_STRICT_REDACT=1` for a harder refuse-to-save gate)
- Default brain is offline; I never auto-switch to a paid/cloud model
- HexStrike: prefer Docker compose (host loopback, no targets mount). See
  [integrations/hexstrike/PROVENANCE.md](integrations/hexstrike/PROVENANCE.md)
- Read `docs/OPERATING_RULES.md` and `docs/SAFETY_MODEL.md` before real hunting

## Lockfile

Runtime pins: `requirements.lock` (from `requirements.in`). Refresh with
`pip-compile requirements.in -o requirements.lock`.

## Low-level commands

Still available if you want scripting: `hackbot scope-check`, `hackbot run`, etc.
See [docs/CLI.md](docs/CLI.md).

## Layout

```text
hackbot/
  repl.py           # interactive agent
  agent.py          # think + tool loop
  local_agent.py    # offline rule-based brain (no model)
  tools.py          # scope, knowledge, plan, run, evidence...
  providers.py      # model-agnostic provider registry + effort levels
  llm.py            # OpenAI-wire / Anthropic-wire transport
  codex_backend.py  # bridge to `codex exec` (your ChatGPT plan)
  ui.py             # Rich terminal UI
  ...
targets/            # per-program workspaces
bounty_knowledge/   # study notes
```
