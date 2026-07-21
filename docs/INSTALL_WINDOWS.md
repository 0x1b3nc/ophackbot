# Install on Windows

## What I need

- Python 3.10+
- Git
- A terminal that likes color (Windows Terminal is fine)
- Optional on PATH: `httpx`, `katana`, `nuclei`, `ffuf`, `curl`

## Setup

```powershell
cd C:\hackbot\hackbot-kit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## API key (required for agent mode)

```powershell
setx ANTHROPIC_API_KEY "your-key"
# or: setx OPENAI_API_KEY "your-key"
```

Close and reopen the terminal so the env var sticks.

## Smoke test

```powershell
# agent REPL (needs API key)
.\.venv\Scripts\python.exe -m hackbot

# low-level (no API key)
.\.venv\Scripts\python.exe -m hackbot target-init demo
.\.venv\Scripts\python.exe -m hackbot scope-check targets/demo --host example.com
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Optional: HexStrike

Third party. High trust surface. Binds `127.0.0.1` only. Prefer Docker without
mounting `targets/`. Read `integrations/hexstrike/PROVENANCE.md` first.

```powershell
cd integrations\hexstrike
python -m venv hexstrike-env
.\hexstrike-env\Scripts\Activate.ps1
pip install pip-tools
pip-compile requirements.txt -o requirements.lock
pip install -r requirements.lock
python hexstrike_server.py --port 8888
```

Health check: `curl http://127.0.0.1:8888/health`

## Lockfile for the kit

Runtime pins live in `requirements.lock`. Refresh with:

```powershell
.\.venv\Scripts\pip-compile requirements.in -o requirements.lock
```

## Notes from me

- Active tools only run with `hackbot run ... --approve`
- Real program data stays under `targets/<program>/` and out of public git
- Set `RECONFTW_PATH` if reconFTW isn't on PATH
