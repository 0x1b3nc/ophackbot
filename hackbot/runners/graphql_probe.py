"""GraphQL introspection + basic probe (authorized targets only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}
""".strip()


def graphql_probe(
    target_dir: Path,
    url: str,
    *,
    query: str | None = None,
    approve: bool = False,
    force: bool = False,
    timeout: float = 15.0,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="graphql introspection probe", force=force)
    body_q = query or INTROSPECTION
    plan = {"url": url, "introspection": query is None, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="graphql_probe", lexer="json")
    cmd = ["graphql_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    payload_bytes = json.dumps({"query": body_q}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload_bytes,
        method="POST",
        headers={
            "User-Agent": "hackbot-graphql-probe",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", None) or resp.getcode())
            raw = resp.read(500_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(200_000).decode("utf-8", errors="replace") if exc.fp else ""
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(cmd, True, 1, "", str(exc), f"error:{type(exc).__name__}")

    introspection_ok = False
    type_names: list[str] = []
    try:
        data = json.loads(raw)
        schema = (data.get("data") or {}).get("__schema")
        if schema:
            introspection_ok = True
            for t in schema.get("types") or []:
                name = t.get("name")
                if name and not str(name).startswith("__"):
                    type_names.append(str(name))
    except json.JSONDecodeError:
        data = {"raw": redact_text(raw[:500])}

    out: dict[str, Any] = {
        "ok": True,
        "url": url,
        "status": status,
        "introspection_enabled": introspection_ok,
        "type_count": len(type_names),
        "types_sample": type_names[:40],
        "signal": introspection_ok,
        "reason": "introspection enabled" if introspection_ok else "no __schema in response",
        "preview": redact_text(raw[:400]),
        "mutation_type": None,
    }
    try:
        schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
        if schema and schema.get("mutationType"):
            out["mutation_type"] = (schema.get("mutationType") or {}).get("name")
            out["reason"] = "introspection open + mutations present"
    except Exception:  # noqa: BLE001
        pass
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
