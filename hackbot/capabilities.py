"""Operator-visible stack: binaries, HexStrike/Burp, packs, Cursor tools."""

from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from typing import Any

from . import ui
from .tool_packs import PACKS, filter_tool_specs, resolve_packs


def _which(name: str) -> str | None:
    return shutil.which(name)


def _http_ok(url: str, *, timeout: float = 1.5) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "hackbot-caps/1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — loopback health
            code = getattr(resp, "status", None) or resp.getcode()
            body = resp.read(200).decode("utf-8", errors="replace")
            return 200 <= int(code) < 300, f"HTTP {code} {body[:80]!r}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _binaries() -> list[dict[str, Any]]:
    names = (
        "httpx",
        "katana",
        "nuclei",
        "ffuf",
        "gau",
        "subfinder",
        "go",
        "burpsuite",
        "curl",
        "docker",
        "adb",
        "frida",
    )
    rows: list[dict[str, Any]] = []
    for name in names:
        path = _which(name)
        rows.append({"name": name, "ok": bool(path), "path": path or ""})
    # Playwright Chromium (optional)
    pw_ok = False
    pw_detail = "not installed"
    try:
        import playwright  # noqa: F401

        cache = os.path.expanduser("~/.cache/ms-playwright")
        if os.name == "nt":
            cache = os.path.join(os.environ.get("USERPROFILE") or "", "AppData", "Local", "ms-playwright")
        pw_ok = os.path.isdir(cache) and any(os.scandir(cache))
        pw_detail = "chromium cache present" if pw_ok else "package ok, run: playwright install chromium"
    except ImportError:
        pw_detail = "pip install missing playwright"
    rows.append({"name": "playwright", "ok": pw_ok, "path": pw_detail})
    return rows


def _hexstrike() -> dict[str, Any]:
    from .config import get_config

    base = (get_config().integrations.hexstrike_server or "http://127.0.0.1:8888").rstrip("/")
    ok, detail = _http_ok(f"{base}/health")
    return {
        "name": "hexstrike",
        "ok": ok,
        "url": base,
        "detail": detail if ok else f"down ({detail}) — start: hackbot run hexstrike --approve",
    }


def _burp() -> dict[str, Any]:
    base = (os.environ.get("HACKBOT_BURP_BASE") or "http://127.0.0.1:1337").rstrip("/")
    ok, detail = _http_ok(f"{base}/")
    # Burp often 404s on / but still up — treat any HTTP response as up
    up = ok or detail.startswith("HTTP ")
    return {
        "name": "burp_rest",
        "ok": up,
        "url": base,
        "detail": detail if up else f"down ({detail}) — set HACKBOT_BURP_BASE if needed",
    }


def _oob() -> dict[str, Any]:
    interact = os.environ.get("HACKBOT_INTERACTSH", "").strip().lower() in {"1", "true", "yes", "on"}
    oob = bool(os.environ.get("HACKBOT_OOB_BASE", "").strip())
    ok = interact or oob
    detail = "interactsh" if interact else ("OOB_BASE" if oob else "unset (blind SSRF limited)")
    return {"name": "oob", "ok": ok, "detail": detail}


def _packs_snapshot(prompt: str = "") -> dict[str, Any]:
    from .cursor_tools import cursor_tools_enabled
    from .tools import TOOL_SPECS

    packs = resolve_packs(prompt)
    specs = filter_tool_specs(TOOL_SPECS, packs)
    names = sorted({str(s.get("name") or "") for s in specs if s.get("name")})
    return {
        "env": os.environ.get("HACKBOT_TOOL_PACK") or "auto",
        "packs": packs,
        "tool_count": len(names),
        "sample": names[:24],
        "cursor_tools": cursor_tools_enabled(),
        "has_run_tool": "run_tool" in names,
        "has_map_surface": "map_surface" in names,
        "has_browser": any(n.startswith("browser_") for n in names),
    }


def collect_capabilities(*, prompt: str = "", probe_network: bool = True) -> dict[str, Any]:
    """Full stack snapshot for /status, /tools, and the capabilities tool."""
    bins = _binaries()
    integ: list[dict[str, Any]] = [_oob()]
    if probe_network:
        integ.extend([_hexstrike(), _burp()])
    else:
        integ.extend(
            [
                {"name": "hexstrike", "ok": False, "detail": "skipped"},
                {"name": "burp_rest", "ok": False, "detail": "skipped"},
            ]
        )
    packs = _packs_snapshot(prompt)
    ready_bins = [b["name"] for b in bins if b.get("ok")]
    missing_bins = [b["name"] for b in bins if not b.get("ok")]
    from .yolo import is_yolo

    return {
        "ok": True,
        "yolo": is_yolo(),
        "binaries": bins,
        "ready_binaries": ready_bins,
        "missing_binaries": missing_bins,
        "integrations": integ,
        "packs": packs,
        "how": {
            "recon_cli": "run_tool tool=httpx|katana|nuclei|ffuf (needs approve; auto under /yolo)",
            "hexstrike": "run_tool tool=hexstrike --approve  then health on :8888",
            "surface": "map_surface / extract_page / analyze_js (pack recon)",
            "browser": "HACKBOT_TOOL_PACK include browser, or say 'browser' in prompt",
            "lab": "stack_prepare / burp_ensure / lab_exec (sudo via .hackbot/sudo_pass)",
            "yolo": "/yolo on → skip y/n (OOS still blocked; step mode still pauses)",
            "step_mode": "HACKBOT_STEP_MODE=1 (default) pause after each hunt act; =0 full budget",
            "all_tools": "HACKBOT_TOOL_PACK=all",
        },
    }


def print_capabilities(caps: dict[str, Any] | None = None, *, compact: bool = False) -> None:
    """Render stack status for the operator."""
    data = caps or collect_capabilities()
    ui.rule("stack / capabilities")

    packs = data.get("packs") or {}
    ui.kv("yolo", "ON" if data.get("yolo") else "off")
    ui.kv("tool_pack", f"{packs.get('env')} → {','.join(packs.get('packs') or [])}")
    ui.kv("hackbot tools", str(packs.get("tool_count") or 0))
    ui.kv(
        "cursor CustomTools",
        "ON" if packs.get("cursor_tools") else "OFF (HACKBOT_CURSOR_TOOLS=0)",
    )
    flags = []
    if packs.get("has_run_tool"):
        flags.append("run_tool")
    if packs.get("has_map_surface"):
        flags.append("map_surface")
    if packs.get("has_browser"):
        flags.append("browser_*")
    ui.kv("key tools in pack", ", ".join(flags) or "(none — widen HACKBOT_TOOL_PACK)")

    if not compact:
        ui.rule("binaries (PATH)")
        for row in data.get("binaries") or []:
            mark = "ok" if row.get("ok") else "missing"
            detail = row.get("path") or ""
            ui.kv(str(row.get("name")), f"{mark}  {detail}".rstrip())

        ui.rule("integrations")
        for row in data.get("integrations") or []:
            mark = "up" if row.get("ok") else "down"
            extra = row.get("url") or row.get("detail") or ""
            ui.kv(str(row.get("name")), f"{mark}  {extra}")

        how = data.get("how") or {}
        ui.rule("how to use")
        for key, tip in how.items():
            ui.info(f"{key}: {tip}")
    else:
        ready = ", ".join(data.get("ready_binaries") or []) or "(none)"
        missing = ", ".join(data.get("missing_binaries") or []) or "(none)"
        ui.kv("bins ready", ready)
        ui.kv("bins missing", missing)
        for row in data.get("integrations") or []:
            ui.kv(str(row.get("name")), "up" if row.get("ok") else "down")


def compact_line(caps: dict[str, Any] | None = None) -> str:
    """One-line summary for cursor turn banners."""
    data = caps or collect_capabilities(probe_network=True)
    packs = data.get("packs") or {}
    ready = data.get("ready_binaries") or []
    integ = data.get("integrations") or []
    hs = next((i for i in integ if i.get("name") == "hexstrike"), {})
    burp = next((i for i in integ if i.get("name") == "burp_rest"), {})
    return (
        f"packs={','.join(packs.get('packs') or [])} tools={packs.get('tool_count')} "
        f"bins={','.join(ready[:6]) or '-'} "
        f"hexstrike={'up' if hs.get('ok') else 'down'} "
        f"burp={'up' if burp.get('ok') else 'down'}"
    )


def as_json(caps: dict[str, Any] | None = None) -> str:
    return json.dumps(caps or collect_capabilities(), ensure_ascii=False, indent=2)
