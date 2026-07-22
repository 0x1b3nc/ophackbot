# Install on Linux

## What I need

- Python 3.10+
- Git
- Optional on PATH: `httpx`, `katana`, `nuclei`, `ffuf`, `curl`

## Setup

```bash
cd /path/to/hackbot-kit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## API keys (optional)

Offline works with zero keys. Only set one if you want `/provider openai` etc.

```bash
export ANTHROPIC_API_KEY="your-key"
# or: export OPENAI_API_KEY="your-key"
# Cursor: export CURSOR_API_KEY="cursor_..."
# Codex: codex login (no API key)
```

## Smoke test

```bash
python -m hackbot                 # REPL (offline by default)
python -m hackbot ui              # browser chat UI → http://127.0.0.1:8765/
python -m hackbot demo
python -m hackbot target-init demo
python -m hackbot scope-check targets/demo --host example.com
python -m pytest -q
```

Also: `playwright install chromium` if you want browser tools.

## Optional: HexStrike

Third party. High trust surface. Binds `127.0.0.1` only. Prefer Docker without
mounting `targets/`. Read `integrations/hexstrike/PROVENANCE.md` first.

```bash
cd integrations/hexstrike
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install pip-tools
pip-compile requirements.txt -o requirements.lock
pip install -r requirements.lock
python3 hexstrike_server.py --port 8888
```

Health check: `curl http://127.0.0.1:8888/health`

## Lockfile for the kit

Runtime pins live in `requirements.lock`. Refresh with:

```bash
pip-compile requirements.in -o requirements.lock
```

## Notes from me

- Active tools only run with `hackbot run ... --approve`
- Real program data stays under `targets/<program>/` and out of public git
- Set `RECONFTW_PATH` if reconFTW isn't on PATH
