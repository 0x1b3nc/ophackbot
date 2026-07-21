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

```powershell
cd integrations\hexstrike
python -m venv hexstrike-env
.\hexstrike-env\Scripts\Activate.ps1
pip install -r requirements.txt
python hexstrike_server.py --port 8888
```

## Notes from me

- Active tools only run with `hackbot run ... --approve`
- Real program data stays under `targets/<program>/` and out of public git
- Set `RECONFTW_PATH` if reconFTW isn't on PATH
