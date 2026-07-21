"""Burp export helpers: XML/HAR summarize + surface seed + optional REST health."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import ui
from ..evidence import EvidenceStore
from ..hunt_memory import Endpoint, HuntMemory
from ..redaction import redact_text
from .base import RunnerResult


def summarize_xml(
    target_dir: Path,
    xml_path: Path,
    *,
    approve: bool = False,
    limit: int = 20,
) -> RunnerResult:
    """
    Read a Burp XML export and write a redacted summary into evidence/safe/.
    Never prints cookie/Authorization values. Does not execute network traffic.
    approve is accepted for CLI symmetry; parsing is always local-only.
    """
    del approve  # local-only; no remote execution path
    if not xml_path.exists():
        msg = f"missing burp export: {xml_path}"
        ui.error(msg)
        return RunnerResult([], False, None, "", "", msg)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    lines: list[str] = [f"# Burp summary from {xml_path.name}", ""]
    count = 0
    hosts: set[str] = set()
    for item in root.iter("item"):
        if count >= limit:
            lines.append(f"... truncated after {limit} items")
            break
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "").strip()
        status = (item.findtext("status") or "").strip()
        path = (item.findtext("path") or "").strip()
        if url:
            host = urlparse(url).netloc.split(":")[0]
            if host:
                hosts.add(host)
        lines.append(f"- {method} {redact_text(url or path)} status={status}")
        count += 1

    body = "\n".join(lines) + "\n"
    if hosts:
        body += "\n## Hosts\n" + "\n".join(f"- {h}" for h in sorted(hosts)) + "\n"
    store = EvidenceStore(target_dir)
    saved = store.save("burp_summary.md", body, keep_raw=False)
    ui.success(f"wrote redacted summary ({count} items)")
    ui.path_line("path", str(saved))
    return RunnerResult(
        command=["burp-summarize", str(xml_path)],
        executed=True,
        returncode=0,
        stdout=body,
        stderr="",
        message=str(saved),
    )


def seed_surface_from_xml(
    target_dir: Path,
    xml_path: Path,
    *,
    limit: int = 300,
) -> dict[str, Any]:
    """Parse Burp XML items into hunt/surface.yaml (local-only)."""
    if not xml_path.exists():
        return {"ok": False, "error": f"missing: {xml_path}"}
    tree = ET.parse(xml_path)
    root = tree.getroot()
    endpoints: list[Endpoint] = []
    hosts: set[str] = set()
    for item in root.iter("item"):
        if len(endpoints) >= limit:
            break
        url = (item.findtext("url") or "").strip()
        if not url:
            continue
        method = (item.findtext("method") or "GET").strip().upper() or "GET"
        parsed = urlparse(url)
        if parsed.netloc:
            hosts.add(parsed.netloc.split(":")[0])
        params = list(parse_qs(parsed.query).keys())
        endpoints.append(
            Endpoint(
                url=url.split("#")[0],
                method=method,
                params=sorted(set(params)),
                source="burp_xml",
            )
        )
    memory = HuntMemory(target_dir)
    host = next(iter(hosts), "")
    if endpoints:
        memory.upsert_endpoints(endpoints, host=host)
    # Also write a quick summary
    summarize_xml(target_dir, xml_path, limit=min(40, limit))
    return {
        "ok": True,
        "path": str(xml_path),
        "endpoints_seeded": len(endpoints),
        "hosts": sorted(hosts),
        "surface": str(memory.root / "surface.yaml"),
    }


def burp_rest_health(
    *,
    base_url: str = "http://127.0.0.1:1337",
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Probe local Burp REST / MCP-ish HTTP endpoints (best-effort).

    Common community setups expose different ports. We try a few paths and
    report what answered — never sends traffic to in-scope targets here.
    """
    bases = [base_url.rstrip("/")]
    # Also try a couple of common alternates if default fails
    for alt in ("http://127.0.0.1:8090", "http://127.0.0.1:8080"):
        if alt not in bases:
            bases.append(alt)

    tried: list[dict[str, Any]] = []
    for base in bases:
        for path in ("/", "/burp", "/v0.1/", "/api/", "/mcp"):
            url = base + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "hackbot-burp-rest"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = int(getattr(resp, "status", None) or resp.getcode())
                    body = resp.read(2000).decode("utf-8", errors="replace")
                tried.append(
                    {
                        "url": url,
                        "status": status,
                        "preview": redact_text(body[:200]),
                        "up": True,
                    }
                )
                return {
                    "ok": True,
                    "up": True,
                    "base": base,
                    "path": path,
                    "status": status,
                    "tried": tried,
                    "control_plane": "rest_health",
                    "hint": (
                        "Burp HTTP listener responded. Use burp_issue_list / burp_proxy_history "
                        "when API paths exist, or export XML/HAR → import_burp_xml / import_har. "
                        "MCP stdio bridge remains optional (HACKBOT_BURP_MCP_CMD)."
                    ),
                }
            except Exception as exc:  # noqa: BLE001
                tried.append({"url": url, "up": False, "error": type(exc).__name__})
    return {
        "ok": True,
        "up": False,
        "tried": tried,
        "hint": (
            "No local Burp REST endpoint found. Export Proxy history as XML or HAR, "
            "then: importa o burp.xml / traffic.har"
        ),
    }


def burp_proxy_history(
    *,
    base_url: str = "http://127.0.0.1:1337",
    timeout: float = 5.0,
    limit: int = 20,
) -> dict[str, Any]:
    """Best-effort fetch of Burp REST proxy history (local only)."""
    health = burp_rest_health(base_url=base_url, timeout=timeout)
    if not health.get("up"):
        return {"ok": False, "error": "burp_not_up", **health}
    base = str(health.get("base") or base_url).rstrip("/")
    items: list[dict[str, Any]] = []
    for path in ("/burp/target/proxyhistory", "/v0.1/proxy/history", "/api/proxy/history"):
        url = base + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hackbot-burp-history"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(100_000).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {"raw": redact_text(body[:500])}
            if isinstance(data, list):
                items = data[:limit]
            elif isinstance(data, dict):
                items = list(data.get("data") or data.get("history") or data.get("items") or [])[:limit]
            return {"ok": True, "path": path, "count": len(items), "items": items, "base": base}
        except Exception as exc:  # noqa: BLE001
            continue
    return {
        "ok": False,
        "error": "history_endpoint_missing",
        "hint": "Export HAR/XML instead — this Burp build has no history REST path.",
        "base": base,
    }


def burp_issue_list(
    *,
    base_url: str = "http://127.0.0.1:1337",
    timeout: float = 5.0,
    limit: int = 20,
) -> dict[str, Any]:
    """Best-effort Burp scanner issues list (local REST)."""
    health = burp_rest_health(base_url=base_url, timeout=timeout)
    if not health.get("up"):
        return {"ok": False, "error": "burp_not_up", **health}
    base = str(health.get("base") or base_url).rstrip("/")
    for path in ("/burp/scanner/issues", "/v0.1/scan/issues", "/api/issues"):
        url = base + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hackbot-burp-issues"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(100_000).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = {"raw": redact_text(body[:500])}
            issues = data if isinstance(data, list) else list(data.get("issues") or data.get("data") or [])[:limit]
            return {"ok": True, "path": path, "count": len(issues), "issues": issues[:limit], "base": base}
        except Exception:  # noqa: BLE001
            continue
    return {"ok": False, "error": "issues_endpoint_missing", "base": base}


def _burp_base() -> str:
    import os

    return (os.environ.get("HACKBOT_BURP_BASE") or "http://127.0.0.1:1337").strip().rstrip("/")


def _burp_headers() -> dict[str, str]:
    import os

    headers = {"User-Agent": "hackbot-burp-cp", "Content-Type": "application/json"}
    key = (os.environ.get("HACKBOT_BURP_API_KEY") or "").strip()
    if key:
        headers["Authorization"] = key if " " in key else f"Bearer {key}"
    return headers


def burp_replay_request(
    target_dir: Path,
    *,
    url: str,
    method: str = "GET",
    body: str = "",
    headers: dict[str, str] | None = None,
    approve: bool = False,
    force: bool = False,
    base_url: str = "",
    timeout: float = 20.0,
    prefer_mcp: bool = True,
) -> dict[str, Any]:
    """
    Control-plane replay: try Burp REST send paths, optional MCP stdio, else
    scoped http_request fallback (still approve/SCOPE gated).
    """
    from ..policy_guard import host_from_target
    from .base import require_in_scope

    require_in_scope(target_dir, url, action="burp replay / send request", force=force)
    method_u = (method or "GET").upper()
    plan = {
        "url": url,
        "method": method_u,
        "approve": approve,
        "burp_base": base_url or _burp_base(),
        "mcp": bool(__import__("os").environ.get("HACKBOT_BURP_MCP_CMD")),
    }
    ui.code_panel(json.dumps(plan, indent=2), title="burp_replay", lexer="json")
    if not approve:
        ui.dry_run_banner()
        return {"ok": True, "dry_run": True, **plan}

    # 1) Optional MCP bridge
    if prefer_mcp and (__import__("os").environ.get("HACKBOT_BURP_MCP_CMD") or "").strip():
        mcp = burp_mcp_call(
            "send_http_request",
            {
                "url": url,
                "method": method_u,
                "body": body or "",
                "headers": headers or {},
            },
        )
        if mcp.get("ok") and not mcp.get("error"):
            return {
                "ok": True,
                "via": "mcp",
                "host": host_from_target(url),
                "result": mcp,
            }

    # 2) REST send/replay guesses (community extensions vary)
    base = (base_url or _burp_base()).rstrip("/")
    payload = {
        "url": url,
        "method": method_u,
        "headers": headers or {},
        "body": body or "",
    }
    tried: list[dict[str, Any]] = []
    for path in (
        "/burp/v0.1/proxy/request",
        "/v0.1/proxy/request",
        "/burp/proxy/request",
        "/api/v1/request",
        "/api/request/send",
    ):
        endpoint = base + path
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers=_burp_headers(),
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                raw = resp.read(100_000).decode("utf-8", errors="replace")
            tried.append({"path": path, "status": status, "up": True})
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"raw": redact_text(raw[:400])}
            return {
                "ok": True,
                "via": "rest",
                "path": path,
                "base": base,
                "status": status,
                "response": data,
                "tried": tried,
            }
        except Exception as exc:  # noqa: BLE001
            tried.append({"path": path, "up": False, "error": type(exc).__name__})

    # 3) Fallback: direct scoped HTTP (operator still approved)
    from . import http_request as http_mod

    result = http_mod.http_request(
        target_dir,
        url,
        method=method_u,
        body=body or None,
        approve=True,
        force=force,
        timeout=timeout,
        label="burp_fallback_http",
        extra_headers=headers or {},
    )
    try:
        detail = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        detail = {"raw": result.stdout}
    return {
        "ok": True,
        "via": "http_fallback",
        "hint": "Burp REST/MCP unavailable — replayed via scoped http_request",
        "tried": tried,
        "response": detail,
        "message": result.message,
    }


def burp_mcp_call(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    _tried: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Best-effort JSON-RPC call over HACKBOT_BURP_MCP_CMD stdio (capped)."""
    import os
    import shutil
    import subprocess

    cmd = (os.environ.get("HACKBOT_BURP_MCP_CMD") or "").strip()
    if not cmd:
        return {"ok": False, "error": "HACKBOT_BURP_MCP_CMD not set"}
    parts = cmd if isinstance(cmd, list) else cmd.split()
    if not parts or (not shutil.which(parts[0]) and not Path(parts[0]).exists()):
        return {"ok": False, "error": "mcp_cmd_not_found", "cmd": parts[:1]}

    def _rpc(method: str, params: dict[str, Any] | None, msg_id: int) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}

    messages = [
        _rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "hackbot", "version": "0.1"},
            },
            1,
        ),
        _rpc("tools/list", {}, 2),
        _rpc("tools/call", {"name": tool_name, "arguments": arguments or {}}, 3),
    ]
    try:
        proc = subprocess.Popen(
            parts,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdin and proc.stdout
        replies: list[dict[str, Any]] = []
        for msg in messages:
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()
            out_line = proc.stdout.readline()
            if not out_line:
                break
            try:
                replies.append(json.loads(out_line))
            except json.JSONDecodeError:
                replies.append({"raw": out_line[:300]})
        try:
            proc.stdin.close()
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        call = next((r for r in reversed(replies) if r.get("id") == 3), replies[-1] if replies else {})
        if call.get("error"):
            tried = _tried + (tool_name,)
            for alt in ("http_request", "repeater_send", "send_request", "proxy_send"):
                if alt not in tried:
                    return burp_mcp_call(alt, arguments, _tried=tried)
            return {"ok": False, "error": call.get("error"), "replies": replies[:3]}
        return {"ok": True, "tool": tool_name, "result": call.get("result"), "replies_count": len(replies)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def burp_replay_from_history(
    target_dir: Path,
    *,
    index: int = 0,
    approve: bool = False,
    force: bool = False,
    base_url: str = "",
) -> dict[str, Any]:
    """Fetch proxy history item N and replay it through burp_replay_request."""
    hist = burp_proxy_history(base_url=base_url or _burp_base(), limit=max(5, index + 1))
    if not hist.get("ok"):
        return hist
    items = list(hist.get("items") or [])
    if index < 0 or index >= len(items):
        return {"ok": False, "error": "history_index_oob", "count": len(items)}
    item = items[index] if isinstance(items[index], dict) else {}
    url = str(item.get("url") or item.get("request", {}).get("url") or "")
    method = str(item.get("method") or item.get("request", {}).get("method") or "GET")
    body = str(item.get("body") or item.get("request", {}).get("body") or "")
    if not url:
        return {"ok": False, "error": "history_item_missing_url", "item_keys": list(item.keys())[:20]}
    out = burp_replay_request(
        target_dir,
        url=url,
        method=method,
        body=body,
        approve=approve,
        force=force,
        base_url=base_url,
    )
    out["history_index"] = index
    out["history_url"] = url
    return out
