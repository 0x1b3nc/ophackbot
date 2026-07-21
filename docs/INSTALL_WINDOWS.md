# Install on Windows

## Requirements

- Python 3.10+
- Git
- Optional tools on PATH: `httpx`, `katana`, `nuclei`, `ffuf`, `curl`

## Setup

```powershell
cd C:\hackbot\hackbot-kit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Smoke test

```powershell
python -m hackbot target-init demo
python -m hackbot scope-check targets/demo --host example.com
python -m unittest discover -s tests -v
```

## Optional: HexStrike

```powershell
cd integrations\hexstrike
python -m venv hexstrike-env
.\hexstrike-env\Scripts\Activate.ps1
pip install -r requirements.txt
python hexstrike_server.py --port 8888
```

## Notes

- Active tools only run with `hackbot run ... --approve`.
- Keep real program data under `targets/<program>/` and out of public git.
- Set `RECONFTW_PATH` if reconFTW is not on PATH.
