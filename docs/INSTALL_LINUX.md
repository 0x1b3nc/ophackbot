# Install on Linux

## Requirements

- Python 3.10+
- Git
- Optional tools on PATH: `httpx`, `katana`, `nuclei`, `ffuf`, `curl`

## Setup

```bash
cd /path/to/hackbot-kit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Smoke test

```bash
python -m hackbot target-init demo
python -m hackbot scope-check targets/demo --host example.com
python -m unittest discover -s tests -v
```

## Optional: HexStrike

```bash
cd integrations/hexstrike
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install -r requirements.txt
python3 hexstrike_server.py --port 8888
```

## Notes

- Active tools only run with `hackbot run ... --approve`.
- Keep real program data under `targets/<program>/` and out of public git.
- Set `RECONFTW_PATH` if reconFTW is not on PATH.
