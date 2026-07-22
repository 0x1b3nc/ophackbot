# Toad + hackbot (visual CLI)

Hackbot stays a **Python hunt kit**. The polished terminal UI is
**[Toad](https://github.com/batrachianai/toad)** (Textual), which talks to agents
over the [Agent Client Protocol](https://agentclientprotocol.com/) (ACP).

We do **not** vendor Toad (AGPL). Install it separately; run hackbot as an ACP
agent.

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
| SCOPE / YOLO | Rails stay in the kit; ACP sessions enable YOLO (OOS still blocked) |

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
