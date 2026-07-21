# HexStrike provenance and containment

This directory vendors a third party offensive toolkit (HexStrike AI MCP Agents).
I did not write the payload generators or shell runners inside
`hexstrike_server.py`. Treat it as high trust surface: it can execute system
commands and generate exploit payloads as part of its normal job.

## What I changed in this kit

- Bind address forced to `127.0.0.1` (loopback only). Never expose it on the LAN
  or the public internet.
- No other edits to HexStrike's offensive logic.

## Integrity pin

```text
file:   hexstrike_server.py
sha256: fefea38b447650ceeb7cfc882fe6497b1345ce6a8b605f4e84e336607a6e078b
```

Recompute after any edit:

```powershell
python -c "import hashlib; from pathlib import Path; print(hashlib.sha256(Path('hexstrike_server.py').read_bytes()).hexdigest())"
```

## How I run it safely

1. Separate venv under `integrations/hexstrike/` (never mix with the kit venv).
2. Keep it on `127.0.0.1` only. Prefer Docker without mounting `targets/`.
3. Do not put cookies, session dumps, or `targets/*/evidence` inside the
   HexStrike container filesystem if you can avoid it.
4. Pin deps when you install:

```powershell
cd integrations\hexstrike
python -m venv hexstrike-env
.\hexstrike-env\Scripts\python.exe -m pip install pip-tools
.\hexstrike-env\Scripts\pip-compile requirements.txt -o requirements.lock
.\hexstrike-env\Scripts\python.exe -m pip install -r requirements.lock
python hexstrike_server.py --port 8888
```

5. Health check stays local: `curl http://127.0.0.1:8888/health`

## Upstream

Track the upstream project you copied from and the date you vendored it. If you
update the server file, recompute the sha256 and refresh `requirements.lock`
before trusting it again.
