# HexStrike requirements.lock

I do not ship a full HexStrike lock in the public kit by default (heavy
transitive tree: pwntools, angr, mitmproxy, selenium). Generate one locally
inside the HexStrike venv before you trust the install:

```powershell
cd integrations\hexstrike
python -m venv hexstrike-env
.\hexstrike-env\Scripts\python.exe -m pip install pip-tools
.\hexstrike-env\Scripts\pip-compile requirements.txt -o requirements.lock
.\hexstrike-env\Scripts\python.exe -m pip install -r requirements.lock
```

Keep `requirements.lock` out of git if it is machine specific, or commit it
only after you have reviewed the resolved versions. See PROVENANCE.md.
