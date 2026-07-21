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

## API key (required for agent mode)

```bash
export ANTHROPIC_API_KEY="your-key"
# or: export OPENAI_API_KEY="your-key"
```

## Smoke test

```bash
# agent REPL (needs API key)
python -m hackbot

# low-level (no API key)
python -m hackbot target-init demo
python -m hackbot scope-check targets/demo --host example.com
python -m unittest discover -s tests -v
```

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
