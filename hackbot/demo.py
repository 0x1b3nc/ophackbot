"""Demo end-to-end smoke for targets/demo — proves the pitch without live traffic."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Callable

from . import ui
from .accounts import ensure_accounts_example
from .identity import ensure_example, save_session
from .tools import execute_tool

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "targets" / "demo"

ApproveFn = Callable[[str], bool]


def ensure_demo_workspace() -> Path:
    """Ensure demo SCOPE + fake A/B sessions exist."""
    DEMO.mkdir(parents=True, exist_ok=True)
    scope = DEMO / "SCOPE.md"
    text = scope.read_text(encoding="utf-8", errors="replace") if scope.exists() else ""
    if "demo.hackbot.local" not in text:
        scope.write_text(
            """---
in_scope:
  - example.com
  - demo.hackbot.local
out_of_scope:
  - "*.example.net"
allowed:
  - Passive recon
  - Active testing
  - IDOR / BOLA checks with provided test accounts
prohibited:
  - DoS
  - Credential stuffing against third parties
  - Destructive actions
---

# Scope

Demo program for smoke-testing the kit. Not a real bounty.

Use `example.com` / `demo.hackbot.local` for dry-runs. Fake sessions live in
`secrets/sessions.yaml` (gitignored) — copy from `sessions.example.yaml`.

## Required Headers / Identity

- Bug bounty header optional: `X-Bug-Bounty: hackbot-demo`

## Rate Limits / Automation

- Keep probes capped (kit defaults). Active traffic still needs `approve`.
""",
            encoding="utf-8",
        )
    for name, content in (
        (
            "FINDINGS.md",
            "# Findings\n\nNo confirmed findings yet.\n",
        ),
        (
            "RESUME.md",
            "# Resume\n\n## Last State\n\n- Demo ready\n\n## Safe Next Step\n\n"
            "- Load fake sessions and dry-run hunt\n",
        ),
        ("PLAN.md", "# Plan\n\n- Demo smoke\n"),
    ):
        path = DEMO / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")

    ensure_example(DEMO)
    ensure_accounts_example(DEMO)
    secrets = DEMO / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    example = secrets / "sessions.example.yaml"
    example.write_text(
        """# Fake demo tokens — safe to commit. Copy to sessions.yaml for live kit use.
headers:
  X-Bug-Bounty: hackbot-demo@example.com

sessions:
  A:
    authorization: "Bearer demo-account-A-token-not-real"
  B:
    authorization: "Bearer demo-account-B-token-not-real"
""",
        encoding="utf-8",
    )
    sessions = secrets / "sessions.yaml"
    if not sessions.exists():
        shutil.copy(example, sessions)
    save_session(DEMO, "A", authorization="Bearer demo-account-A-token-not-real")
    save_session(DEMO, "B", authorization="Bearer demo-account-B-token-not-real")

    # Fake login accounts so session_bootstrap dry-run is exercisable
    accounts = secrets / "accounts.yaml"
    if not accounts.exists():
        accounts.write_text(
            """# Fake demo accounts — not real credentials
login:
  path: /login
  method: POST
  user_field: username
  pass_field: password
  csrf_field: csrf_token
accounts:
  A:
    username: demo-user-a
    password: demo-pass-a-not-real
    role: user
  B:
    username: demo-user-b
    password: demo-pass-b-not-real
    role: user
""",
            encoding="utf-8",
        )

    (DEMO / "DEMO.md").write_text(
        """# Hackbot demo pitch

```text
as credenciais estão no arquivo secrets/sessions.yaml
checa o scope de example.com
explora o que der em example.com
compara sessão A vs B em https://example.com/
monta o draft do report
```

Or: `python -m hackbot demo`

Fake A/B tokens prove session load → tools → report without a real program.
""",
        encoding="utf-8",
    )
    return DEMO


def run_demo_smoke(*, approve_writes: bool = True) -> dict[str, Any]:
    """Offline dry-run path that exercises the main tools against demo."""
    ensure_demo_workspace()
    target = str(DEMO)
    steps: list[dict[str, Any]] = []

    def deny(_d: str) -> bool:
        return False

    def allow(_d: str) -> bool:
        return True

    def run(name: str, args: dict[str, Any], *, write: bool = False) -> dict[str, Any]:
        raw = execute_tool(
            name,
            args,
            approve_fn=allow if (write and approve_writes) else deny,
        )
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"raw": raw[:200]}
        err = data.get("error") or (data.get("detail") or {}).get("error")
        soft_ok = err in {
            "playwright_missing",
            "missing_dep",
            "adb_missing",
            "frida_missing",
            "accounts_missing",
        } or bool(data.get("dry_run")) or bool((data.get("detail") or {}).get("dry_run"))
        steps.append(
            {
                "tool": name,
                "ok": data.get("ok", True) is not False or soft_ok,
                "dry_run": data.get("dry_run") or (data.get("detail") or {}).get("dry_run"),
                "error": err,
            }
        )
        return data

    run("scope_check", {"target_dir": target, "host": "example.com"})
    run("show_identity", {"target_dir": target})
    run("hunt_checklist", {"target_dir": target})
    run("show_accounts", {"target_dir": target})
    run(
        "session_bootstrap",
        {"target_dir": target, "base_url": "https://example.com", "approve": False},
    )
    run(
        "idor_probe",
        {
            "target_dir": target,
            "url": "https://example.com/api/orders/1",
            "approve": False,
            "force": True,
        },
    )
    run("browser_navigate", {"target_dir": target, "url": "https://example.com/", "approve": False})
    run(
        "ssrf_probe",
        {"target_dir": target, "url": "https://example.com/?url=1", "param": "url", "approve": False},
    )
    run("race_probe", {"target_dir": target, "url": "https://example.com/", "approve": False})
    run("websocket_probe", {"target_dir": target, "url": "wss://example.com/ws", "approve": False})
    run("learn_stats", {})
    run("mobile_status", {"task": "demo"})
    run("frida_status", {})
    run("mobsf_health", {})

    findings = DEMO / "FINDINGS.md"
    if "C-001" not in findings.read_text(encoding="utf-8", errors="replace"):
        findings.write_text(
            "# Findings\n\n## C-001 Demo IDOR\n\n"
            "- Status: draft\n- Class: idor\n- Verdict: likely\n"
            "- Asset: example.com\n- Endpoint: https://example.com/api/orders/1\n"
            "- Preconditions: A/B demo sessions\n- Observed: dry-run demo\n"
            "- Impact: Demo only\n- Evidence: n/a\n- Next step: draft report\n",
            encoding="utf-8",
        )
    run(
        "write_report_draft",
        {"target_dir": target, "platform": "generic", "finding_id": "latest"},
        write=True,
    )

    summary = {
        "ok": all(s.get("ok") for s in steps),
        "target": target,
        "steps": steps,
        "hint": "See targets/demo/DEMO.md — say approve only for real in-scope traffic.",
    }
    ui.success(f"demo smoke: {len(steps)} steps ok={summary['ok']}")
    return summary


def main() -> None:
    out = run_demo_smoke()
    print(json.dumps({k: out[k] for k in ("ok", "target", "hint")}, indent=2))
    raise SystemExit(0 if out.get("ok") else 1)


if __name__ == "__main__":
    main()
