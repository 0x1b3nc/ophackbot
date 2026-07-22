# Toad + hackbot (optional external host)

**Prefer `python -m hackbot tui`** for a Textual UI with hackbot branding and
slash commands (`/models`, `/target`, …). That app is ours.

This page is only if you still want **[Toad](https://github.com/batrachianai/toad)**
as an external host (AGPL — we do not vendor it). Toad will show its own title
and `/toad:` commands in the picker; that is expected. Use `hackbot tui` to avoid
that.

## Kali / Linux quickstart

```bash
cd ~/testhackbot/ophackbot   # or your clone
source .venv/bin/activate
pip install -U -e '.[acp]'   # agent-client-protocol

# Provider (optional — default offline)
export HACKBOT_PROVIDER=codex   # or cursor
# codex login / CURSOR_API_KEY as usual

# Toad needs a recent Python for `uv tool` (3.14+)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install -U batrachian-toad --python 3.14

# Project cwd = hunt workspace
toad acp "python -m hackbot acp" .
# or absolute: toad acp "$PWD/.venv/bin/python -m hackbot acp" "$PWD"
```

Alternate installer:

```bash
curl -fsSL batrachian.ai/install | sh
toad acp "python -m hackbot acp" .
```

## What happens

| Piece | Role |
| --- | --- |
| Toad | TUI: markdown, prompt editor, shell (`!`), sessions |
| `hackbot acp` | stdio ACP agent → same brains/tools as the REPL |
| SCOPE / YOLO | Rails stay in the kit; ACP sessions enable YOLO (force on, OOS overridable) |

Stdout of `hackbot acp` is **JSON-RPC only**. Rich tool chatter goes to stderr /
the host terminal.

## Catalog entry (optional)

To show hackbot in Toad’s agent list across updates, copy
[`integrations/toad/hackbot.toml`](../integrations/toad/hackbot.toml) into
Toad’s packaged `data/agents/` (inside the uv tool env), or keep launching via
`toad acp "…"`.

## REPL still available

```bash
python -m hackbot          # classic Rich REPL
python -m hackbot ask …    # one-shot
```

`python -m hackbot ui` (browser) is **deprecated**.

## Zed (same ACP agent)

```json
{
  "agent_servers": {
    "hackbot": {
      "type": "custom",
      "command": "/home/you/testhackbot/ophackbot/.venv/bin/python",
      "args": ["-m", "hackbot", "acp"]
    }
  }
}
```
