# Hackbot Kit

CLI and workspace for authorized security research: bug bounty, CTF, owned labs,
contracted pentests, and education. Not for use against systems without permission.

Value comes from scope control, redacted evidence, controlled automation, and
reproducible reports. Not from scanner spam.

## Install

- Windows: [docs/INSTALL_WINDOWS.md](docs/INSTALL_WINDOWS.md)
- Linux: [docs/INSTALL_LINUX.md](docs/INSTALL_LINUX.md)

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
# Linux:   source .venv/bin/activate
python -m pip install -e .
```

## Quick start

```bash
python -m hackbot target-init demo
python -m hackbot scope-check targets/demo --host example.com
python -m hackbot knowledge "IDOR on GraphQL mutation"
python -m hackbot plan targets/demo \
  --hypothesis "Object ID in /api/orders/{id} is not bound to caller" \
  --target https://example.com/api/orders/1 \
  --action "idor read" \
  --command "curl -i https://example.com/api/orders/1"
python -m hackbot run targets/demo --tool httpx --host example.com
# add --approve only after scope/policy review
python -m unittest discover -s tests -v
```

CLI reference: [docs/CLI.md](docs/CLI.md)

## Layout

```text
hackbot/
  cli.py
  policy_guard.py
  planner.py
  knowledge.py
  evidence.py
  redaction.py
  runners/          # httpx, nuclei, katana, ffuf, reconFTW, HexStrike, Burp
  reporting/        # Bugcrowd, HackerOne, Intigriti drafts
configs/
docs/
templates/
  target/           # SCOPE, PLAN, FINDINGS, RESUME
  reports/
bounty_knowledge/   # study notes + routing
targets/            # per-program workspaces (secrets ignored)
```

## Safety

- Every target needs `SCOPE.md`.
- Active runners refuse hosts not confirmed in scope.
- Commands print first; execution requires `--approve`.
- Evidence is redacted (`Authorization`, `Cookie`, tokens, emails, common secrets).
- Read `docs/OPERATING_RULES.md` and `docs/SAFETY_MODEL.md` before hunting.

## Do not commit

Private programs, cookies, tokens, session headers, live HAR/Burp XML,
screenshots with PII, private reports, recon dumps of real companies, or
unlicensed giant wordlists. See `.gitignore`.

## HexStrike (optional)

```bash
cd integrations/hexstrike
python -m venv hexstrike-env
source hexstrike-env/bin/activate   # Windows: .\hexstrike-env\Scripts\Activate.ps1
pip install -r requirements.txt
python hexstrike_server.py --port 8888
```
