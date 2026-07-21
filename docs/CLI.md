# Hackbot CLI

## Agent mode (default)

This is the main UX. Like Claude Code / Codex: you type a task, I think and use tools.
hackbot is the knowledge + safety layer; you bring the model.

```powershell
# open once, stays open (recommended)
.\hackbot.cmd
# or
.\.venv\Scripts\python.exe -m hackbot

# one-shot
.\.venv\Scripts\python.exe -m hackbot check if example.com is in scope for targets/demo
```

### Brains

hackbot picks one automatically, and you can switch live:

- **model**   – any HTTP provider (OpenAI, Anthropic, DeepSeek, GLM, OpenRouter, local)
- **codex**   – the `codex` CLI, powered by your ChatGPT plan (no API credit). `codex login` first.
- **offline** – no model, rule-based planner. Still parses your prompt and runs tools.

### Providers

Set a key (or point at a local model) and hackbot auto-detects it:

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

Force a provider with `HACKBOT_PROVIDER` (openai, anthropic, codex, deepseek, glm,
openrouter, ollama, lmstudio, custom, offline).

### Model + reasoning effort

```powershell
setx HACKBOT_MODEL "o4-mini"          # any model your account supports
setx HACKBOT_EFFORT "high"            # minimal | low | medium | high | xhigh
```

Effort maps to the right knob per provider: OpenAI/Codex `reasoning_effort`,
Anthropic extended-thinking budget, OpenRouter `reasoning.effort`, GLM thinking.
Providers that don't support it just ignore it.

Reopen the terminal after `setx`. Active traffic still asks you to approve.

### REPL commands

```text
/providers            list providers + which have a key
/provider <name>      switch provider (also /codex, /local)
/models               model suggestions for the current provider
/model <name>         set the model
/effort <level>       minimal | low | medium | high | xhigh
/status               show brain + provider + model + effort
/clear   /help   /exit
```

## Low-level commands (optional)

Still there for scripts:

```powershell
.\.venv\Scripts\python.exe -m hackbot cmd
.\.venv\Scripts\python.exe -m hackbot scope-check targets/demo --host example.com
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool httpx --host example.com
```
