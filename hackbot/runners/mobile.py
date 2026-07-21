"""Mobile bounty helpers: tool detection, adb devices, APK inspect (no Frida hooks)."""

from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from .. import ui
from ..evidence import EvidenceStore
from ..redaction import redact_text
from .base import RunnerResult

CHECKLIST = [
    "Proxy the app through Burp (system CA / network_security_config bypass on lab builds).",
    "Export API traffic as HAR → import_har / import_burp_xml into the target.",
    "Set A/B sessions from tokens; hunt IDOR on mobile API hosts in SCOPE.md.",
    "Frida/Objection: SSL unpinning + hook auth only on authorized lab/bounty builds.",
    "MobSF static scan offline; feed interesting URLs back into map_surface.",
]


def _which(name: str) -> str | None:
    return shutil.which(name)


def tool_status() -> dict[str, Any]:
    """Detect local mobile toolchain (honest availability, no remote traffic)."""
    tools = {
        "adb": _which("adb"),
        "frida": _which("frida"),
        "frida-ps": _which("frida-ps"),
        "objection": _which("objection"),
        "aapt": _which("aapt") or _which("aapt2"),
        "apkanalyzer": _which("apkanalyzer"),
    }
    present = {k: bool(v) for k, v in tools.items()}
    paths = {k: v for k, v in tools.items() if v}
    wired = any(present.values())
    return {
        "ok": True,
        "wired": wired,
        "frida_hooking": False,  # never auto-hook
        "tools_present": present,
        "tool_paths": paths,
        "checklist": CHECKLIST,
        "hint": (
            "Use adb_devices / inspect_apk for local recon. "
            "Frida hooks are operator-driven outside hackbot — we only detect CLI presence."
            if wired
            else "No adb/frida/aapt on PATH. Install platform-tools + Frida for lab work; "
            "meanwhile proxy APK → HAR → import_har."
        ),
    }


def adb_devices(*, timeout: float = 8.0) -> dict[str, Any]:
    """List adb devices (local USB/emulator only)."""
    adb = _which("adb")
    if not adb:
        return {
            "ok": True,
            "wired": False,
            "devices": [],
            "error": "adb_missing",
            "hint": "Install Android platform-tools and ensure `adb` is on PATH.",
        }
    try:
        proc = subprocess.run(
            [adb, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}

    devices: list[dict[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        devices.append({"serial": serial, "state": state, "raw": line})
    return {
        "ok": True,
        "wired": True,
        "devices": devices,
        "count": len(devices),
        "stderr": redact_text((proc.stderr or "")[:300]),
    }


def inspect_apk(
    target_dir: Path,
    apk_path: Path,
    *,
    limit_entries: int = 80,
) -> dict[str, Any]:
    """Local APK inspect: zip listing + optional aapt badging. No network."""
    if not apk_path.exists():
        return {"ok": False, "error": f"missing: {apk_path}"}
    if not apk_path.is_file():
        return {"ok": False, "error": "not a file"}

    entries: list[str] = []
    interesting: list[str] = []
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            for name in names[:limit_entries]:
                entries.append(name)
            for name in names:
                lower = name.lower()
                if any(
                    x in lower
                    for x in (
                        "network_security_config",
                        "google-services",
                        "firebase",
                        "api",
                        "cert",
                        "assets/",
                        "lib/",
                    )
                ):
                    interesting.append(name)
                if len(interesting) >= 40:
                    break
    except zipfile.BadZipFile:
        return {"ok": False, "error": "not a zip/apk"}

    badging: str | None = None
    package = ""
    aapt = _which("aapt") or _which("aapt2")
    if aapt:
        try:
            # aapt2 dump badging works; aapt dump badging too
            proc = subprocess.run(
                [aapt, "dump", "badging", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            badging = (proc.stdout or "")[:4000]
            for line in badging.splitlines():
                if line.startswith("package:"):
                    # package: name='com.x' versionCode='1' ...
                    if "name='" in line:
                        package = line.split("name='", 1)[1].split("'", 1)[0]
                    break
        except (OSError, subprocess.TimeoutExpired):
            badging = None

    payload = {
        "ok": True,
        "path": str(apk_path),
        "bytes": apk_path.stat().st_size,
        "entry_sample": entries,
        "entry_count_sample": len(entries),
        "interesting": interesting[:40],
        "package": package or None,
        "aapt_badging_preview": redact_text(badging[:1500]) if badging else None,
        "checklist": CHECKLIST,
        "hint": (
            "Static peek only. For dynamic: proxy through Burp, then import_har. "
            "Frida hooks stay operator-driven."
        ),
    }
    try:
        EvidenceStore(target_dir).save(
            "apk_inspect.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(f"apk inspect: {apk_path.name} package={package or '?'}")
    return payload


def mobile_hint(task: str = "") -> dict[str, Any]:
    status = tool_status()
    status["task"] = task
    status["message"] = status.get("hint")
    return status


def bridge_to_hunt(
    target_dir: Path,
    *,
    apk_path: Path | None = None,
    har_path: Path | None = None,
    start_hunt: bool = False,
    approve: bool = False,
    force: bool = False,
    host: str = "",
    budget: int | None = None,
    prompt: str = "",
) -> dict[str, Any]:
    """APK inspect + HAR import → optional autonomous hunt. Local files only until hunt."""
    from . import har_import as har_import_runner

    target_dir = Path(target_dir)
    steps: list[dict[str, Any]] = []
    hosts: list[str] = []

    if apk_path:
        apk_result = inspect_apk(target_dir, Path(apk_path))
        steps.append({"step": "inspect_apk", "result": {
            "ok": apk_result.get("ok"),
            "package": apk_result.get("package"),
            "interesting_count": len(apk_result.get("interesting") or []),
            "path": apk_result.get("path"),
            "error": apk_result.get("error"),
        }})

    if har_path:
        har = Path(har_path)
        if not har.exists():
            steps.append({"step": "import_har", "result": {"ok": False, "error": f"missing: {har}"}})
        else:
            har_result = har_import_runner.import_har(har, target_dir)
            hosts = list(har_result.get("hosts") or [])
            steps.append(
                {
                    "step": "import_har",
                    "result": {
                        "ok": har_result.get("ok"),
                        "endpoints_seeded": har_result.get("endpoints_seeded"),
                        "hosts": hosts,
                        "entries": har_result.get("entries"),
                    },
                }
            )

    if not apk_path and not har_path:
        return {
            "ok": False,
            "error": "need apk_path and/or har_path",
            "hint": "ex: bridge com app.apk e traffic.har → hunt",
            "checklist": CHECKLIST,
        }

    # Write operator bridge note (redacted)
    note_lines = [
        "# Mobile → hunt bridge",
        "",
        f"- apk: `{apk_path}`" if apk_path else "- apk: (none)",
        f"- har: `{har_path}`" if har_path else "- har: (none)",
        f"- hosts from HAR: {', '.join(hosts) or '(none yet)'}",
        "",
        "## Next",
        "- Ensure API hosts are in SCOPE.md",
        "- Load A/B sessions if API needs auth",
        "- `run_hunt` / `browser_with_session` on the API origin",
        "",
        "## Checklist",
        *[f"- {c}" for c in CHECKLIST],
        "",
    ]
    note = "\n".join(note_lines)
    try:
        EvidenceStore(target_dir).save("mobile_bridge.md", note)
        (Path(target_dir) / "hunt").mkdir(parents=True, exist_ok=True)
        (Path(target_dir) / "hunt" / "mobile_bridge.md").write_text(note, encoding="utf-8")
    except Exception:
        pass

    hunt_result: dict[str, Any] | None = None
    if start_hunt:
        if not approve:
            hunt_result = {
                "ok": True,
                "dry_run": True,
                "hint": "Pass approve=true to start run_hunt after seeding.",
            }
        else:
            from ..hunt_controller import run_hunt

            hunt_host = host or (hosts[0] if hosts else "")
            hunt_prompt = prompt or (
                f"mobile bridge hunt after APK/HAR seed hosts={','.join(hosts[:5])}"
            )
            hunt_result = run_hunt(
                target_dir,
                hunt_prompt,
                host=hunt_host,
                approve_session=True,
                budget=budget,
                force=force,
            )
        steps.append({"step": "run_hunt", "result": {
            k: hunt_result.get(k)
            for k in ("ok", "dry_run", "error", "acts", "findings", "last_summary", "hint")
            if isinstance(hunt_result, dict) and k in hunt_result
        } or hunt_result})

    ok = all(
        (s.get("result") or {}).get("ok", True) is not False
        for s in steps
        if s.get("step") != "run_hunt" or start_hunt
    )
    return {
        "ok": ok,
        "steps": steps,
        "hosts": hosts,
        "start_hunt": start_hunt,
        "hunt": hunt_result,
        "bridge_note": str(Path(target_dir) / "hunt" / "mobile_bridge.md"),
        "hint": (
            "Surface seeded. Say 'explora o que der approve' or pass start_hunt=true."
            if hosts and not start_hunt
            else CHECKLIST[0]
        ),
    }


def run_inspect_apk(target_dir: Path, apk_path: Path) -> RunnerResult:
    result = inspect_apk(target_dir, apk_path)
    ok = bool(result.get("ok"))
    return RunnerResult(
        ["inspect_apk", str(apk_path)],
        ok,
        0 if ok else 1,
        json.dumps(result),
        "",
        "executed" if ok else str(result.get("error") or "error"),
    )
