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

There are three. hackbot starts on offline and never changes it on its own. If I
want a smarter brain I pick one (a key, or `/provider`).

- offline: no model, no network, rule based. It still reads my prompt and runs
  tools. This is home base and the default.
- model: any HTTP provider (OpenAI, Anthropic, DeepSeek, GLM, OpenRouter, or a
  local model). It calls my tools directly.
- codex: the `codex` CLI running on my ChatGPT plan, so it spends plan quota
  instead of paid API credit. Run `codex login` first.

### Providers

Set a key (or point at a local model) and hackbot detects it. It still won't
switch until I ask, so I set `HACKBOT_PROVIDER` or use `/provider` when I want it.

```powershell
setx OPENAI_API_KEY "sk-..."          # OpenAI (paid API)
setx ANTHROPIC_API_KEY "sk-..."       # Claude
setx DEEPSEEK_API_KEY "sk-..."        # DeepSeek
setx GLM_API_KEY "..."                # GLM / Zhipu
setx OPENROUTER_API_KEY "sk-or-..."   # OpenRouter (hundreds of models, one key)
setx HACKBOT_BASE_URL "http://localhost:11434/v1"   # Ollama / LM Studio / any gateway

# ChatGPT plan via Codex CLI (no API cost):
codex login
setx HACKBOT_PROVIDER codex
```

Force a provider with `HACKBOT_PROVIDER`: openai, anthropic, codex, deepseek,
glm, openrouter, ollama, lmstudio, custom, offline.

### Model and reasoning effort

```powershell
setx HACKBOT_MODEL "o4-mini"          # any model your account supports
setx HACKBOT_EFFORT "high"            # minimal, low, medium, high, xhigh
```

Effort maps to whatever knob each provider uses: OpenAI and Codex
`reasoning_effort`, Anthropic thinking budget, OpenRouter `reasoning.effort`, GLM
thinking. Providers that don't have one just ignore it.

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
they happen. That part never gets skipped.

## Low-level commands (optional)

Still here if you want to script things:

```powershell
.\.venv\Scripts\python.exe -m hackbot cmd
.\.venv\Scripts\python.exe -m hackbot scope-check targets/demo --host example.com
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool httpx --host example.com
```
