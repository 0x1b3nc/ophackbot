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
setx HACKBOT_EFFORT "high"   # minimal | low | medium | high | xhigh
```

In the REPL: `/providers`, `/provider <name>`, `/model <name>`, `/effort <level>`, `/status`.
See [docs/CLI.md](docs/CLI.md).

Windows notes: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md)  
Linux notes: [docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md)

## Use it

```powershell
# interactive agent (default)
.\.venv\Scripts\python.exe -m hackbot

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

## Safety

- Every target needs `SCOPE.md`
- Tools refuse hosts I haven't confirmed in scope
- `run_tool` defaults to dry-run; approve asks you first
- **Every file change asks approval** (path + preview) before it happens
- Evidence redacts cookies, tokens, emails, common secrets
- Default brain is offline; I never auto-switch to a paid/cloud model
- Read `docs/OPERATING_RULES.md` before real hunting

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
