"""Lab autonomy: local shell (optional sudo), Go/PATH fix, Burp Community ensure."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui

ROOT = Path(__file__).resolve().parents[2]
HACKBOT_DIR = ROOT / ".hackbot"
SUDO_PASS_FILE = HACKBOT_DIR / "sudo_pass"
BURP_DIR = HACKBOT_DIR / "burp"
BURP_PID_FILE = BURP_DIR / "burp.pid"
BURP_LOG = BURP_DIR / "burp_ensure.log"

# Best-effort REST bridge for Burp (Community has no stock REST on :1337).
# Pinned release asset; checksum verified when download succeeds.
_BURP_REST_JAR_NAME = "burp-rest-api-2.0.1.jar"
_BURP_REST_URL = (
    "https://github.com/vmware/burp-rest-api/releases/download/"
    "2.0.1/burp-rest-api-2.0.1.jar"
)
# sha256 of upstream jar when available; empty → skip strict verify
_BURP_REST_SHA256 = ""

_MAX_OUT = 8000


def _cap(text: str, limit: int = _MAX_OUT) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (+{len(text) - limit} chars)"


def sudo_password() -> str | None:
    """Load sudo password from env or .hackbot/sudo_pass. Never log the value."""
    env = (os.environ.get("HACKBOT_SUDO_PASS") or "").strip()
    if env:
        return env
    try:
        if SUDO_PASS_FILE.is_file():
            return SUDO_PASS_FILE.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None
    return None


def lab_exec(
    command: str | list[str],
    *,
    cwd: str | None = None,
    timeout_sec: float = 120.0,
    sudo: bool = False,
    env_extra: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a local command. Optional sudo via `sudo -S` + local pass file/env."""
    if isinstance(command, list):
        argv = [str(x) for x in command]
        display = " ".join(argv)
    else:
        display = str(command).strip()
        if not display:
            return {"ok": False, "error": "empty command", "kind": "bad_args"}
        argv = ["bash", "-lc", display]

    run_env = os.environ.copy()
    if env_extra:
        run_env.update(env_extra)

    work = Path(cwd).expanduser() if cwd else Path.cwd()
    if not work.is_dir():
        return {"ok": False, "error": f"cwd missing: {work}", "kind": "bad_args"}

    stdin_data: str | None = None
    if sudo:
        pw = sudo_password()
        if not pw:
            return {
                "ok": False,
                "error": (
                    "sudo requested but no password. Set HACKBOT_SUDO_PASS or "
                    f"write it to {SUDO_PASS_FILE} (chmod 600)."
                ),
                "kind": "needs_setup",
            }
        # Wrap: sudo -S runs the real command with password on stdin.
        if isinstance(command, list):
            inner = " ".join(shlex_quote(a) for a in argv)
            argv = ["sudo", "-S", "-p", "", "bash", "-lc", inner]
        else:
            argv = ["sudo", "-S", "-p", "", "bash", "-lc", display]
        stdin_data = pw + "\n"

    try:
        proc = subprocess.run(
            argv,
            cwd=str(work),
            input=stdin_data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=float(timeout_sec),
            env=run_env,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"timed out after {timeout_sec}s",
            "command": display,
            "sudo": bool(sudo),
            "kind": "timeout",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "command": display,
            "sudo": bool(sudo),
        }

    out = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "command": display,
        "sudo": bool(sudo),
        "cwd": str(work),
        "stdout": _cap(proc.stdout or ""),
        "stderr": _cap(_redact_secrets(proc.stderr or "")),
    }
    if not out["ok"]:
        out["error"] = f"exit {proc.returncode}"
    return out


def shlex_quote(s: str) -> str:
    import shlex

    return shlex.quote(s)


def _redact_secrets(text: str) -> str:
    pw = sudo_password()
    if pw and pw in text:
        return text.replace(pw, "***")
    return text


def _ensure_path_dirs(dirs: list[Path]) -> list[str]:
    """Prepend existing dirs to process PATH. Returns list of dirs added."""
    path = os.environ.get("PATH") or ""
    parts = path.split(os.pathsep)
    added: list[str] = []
    for d in dirs:
        s = str(d)
        if d.is_dir() and s not in parts:
            parts.insert(0, s)
            added.append(s)
    if added:
        os.environ["PATH"] = os.pathsep.join(parts)
    return added


def stack_prepare(*, persist_shell_rc: bool = False) -> dict[str, Any]:
    """Fix Go/tool PATH for this process; smoke-check gau/subfinder/httpx."""
    home = Path.home()
    candidates = [
        home / "go" / "bin",
        Path("/usr/local/go/bin"),
        home / ".local" / "bin",
        Path("/usr/bin"),
    ]
    added = _ensure_path_dirs(candidates)

    def which(name: str) -> str | None:
        return shutil.which(name)

    tools = ("go", "gau", "subfinder", "httpx", "katana", "nuclei", "ffuf", "burpsuite")
    found: dict[str, str] = {}
    missing: list[str] = []
    for name in tools:
        p = which(name)
        if p:
            found[name] = p
        else:
            missing.append(name)

    smokes: dict[str, Any] = {}
    for name in ("gau", "subfinder", "httpx"):
        if name not in found:
            smokes[name] = {"ok": False, "error": "not on PATH"}
            continue
        try:
            proc = subprocess.run(
                [found[name], "-h"] if name != "gau" else [found[name], "--help"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
            )
            # many CLIs exit 2 on -h; treat any spawn as ok
            smokes[name] = {
                "ok": True,
                "returncode": proc.returncode,
                "hint": "help ok" if proc.returncode in {0, 1, 2} else f"exit {proc.returncode}",
            }
        except subprocess.TimeoutExpired:
            smokes[name] = {
                "ok": False,
                "error": "help timed out (gau often hangs on live pulls — prefer wayback_urls)",
                "prefer": "wayback_urls / crt_subdomains",
            }
        except OSError as exc:
            smokes[name] = {"ok": False, "error": str(exc)}

    rc_note = ""
    if persist_shell_rc and added:
        line = 'export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"'
        zshrc = home / ".zshrc"
        try:
            existing = zshrc.read_text(encoding="utf-8") if zshrc.is_file() else ""
            if "go/bin" not in existing:
                with zshrc.open("a", encoding="utf-8") as handle:
                    handle.write(f"\n# hackbot stack_prepare\n{line}\n")
                rc_note = f"appended PATH to {zshrc}"
            else:
                rc_note = "zshrc already has go/bin"
        except OSError as exc:
            rc_note = f"could not edit zshrc: {exc}"

    return {
        "ok": True,
        "path_added": added,
        "found": found,
        "missing": missing,
        "smokes": smokes,
        "notes": [
            "HexStrike amass may fail under Docker no-new-privileges — use host subfinder.",
            "gau live pulls can hang — prefer wayback_urls / crt_subdomains or short timeouts.",
            rc_note,
        ],
        "path_now_head": (os.environ.get("PATH") or "")[:200],
    }


def _find_burpsuite() -> str | None:
    for name in ("burpsuite", "burpsuite-community", "BurpSuiteCommunity"):
        p = shutil.which(name)
        if p:
            return p
    for cand in (
        Path("/usr/bin/burpsuite"),
        Path("/usr/share/burpsuite/burpsuite_community.jar"),
        Path("/usr/share/burpsuite/burpsuite.jar"),
        Path.home() / "BurpSuiteCommunity" / "BurpSuiteCommunity",
    ):
        if cand.is_file():
            return str(cand)
    return None


def _download_burp_rest_jar() -> dict[str, Any]:
    BURP_DIR.mkdir(parents=True, exist_ok=True)
    dest = BURP_DIR / _BURP_REST_JAR_NAME
    if dest.is_file() and dest.stat().st_size > 1000:
        return {"ok": True, "path": str(dest), "cached": True}
    try:
        req = urllib.request.Request(
            _BURP_REST_URL,
            headers={"User-Agent": "hackbot-burp-ensure/1"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            data = resp.read()
        if _BURP_REST_SHA256:
            digest = hashlib.sha256(data).hexdigest()
            if digest != _BURP_REST_SHA256:
                return {
                    "ok": False,
                    "error": f"checksum mismatch for {_BURP_REST_JAR_NAME}",
                    "got": digest,
                }
        dest.write_bytes(data)
        return {"ok": True, "path": str(dest), "cached": False, "bytes": len(data)}
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"download failed: {type(exc).__name__}: {exc}",
            "url": _BURP_REST_URL,
            "hint": (
                "Place a burp-rest-api JAR at "
                f"{dest} manually, or start Burp and load a REST extension yourself."
            ),
        }


def _burp_already_up(base: str) -> dict[str, Any] | None:
    from .burp import burp_rest_health

    health = burp_rest_health(base_url=base, timeout=2.0)
    if health.get("up"):
        return health
    return None


def burp_ensure(
    *,
    base_url: str | None = None,
    wait_sec: float = 45.0,
    download_ext: bool = True,
) -> dict[str, Any]:
    """Start Burp Community (best-effort) and wait for a local REST control-plane."""
    base = (base_url or os.environ.get("HACKBOT_BURP_BASE") or "http://127.0.0.1:1337").rstrip(
        "/"
    )
    already = _burp_already_up(base)
    if already:
        os.environ["HACKBOT_BURP_BASE"] = already.get("base") or base
        return {
            "ok": True,
            "up": True,
            "started": False,
            "base": os.environ["HACKBOT_BURP_BASE"],
            "detail": "already up",
            "health": already,
        }

    binary = _find_burpsuite()
    if not binary:
        return {
            "ok": False,
            "up": False,
            "error": "burpsuite binary/jar not found on PATH",
            "hint": "Install Burp Community or put burpsuite on PATH, then retry burp_ensure.",
            "kind": "needs_setup",
        }

    jar_info: dict[str, Any] = {"skipped": not download_ext}
    jar_path = ""
    if download_ext:
        jar_info = _download_burp_rest_jar()
        if jar_info.get("ok"):
            jar_path = str(jar_info.get("path") or "")

    BURP_DIR.mkdir(parents=True, exist_ok=True)

    display = os.environ.get("DISPLAY", "").strip()
    use_xvfb = not display and bool(shutil.which("xvfb-run"))

    # Launch strategy: prefer system burpsuite launcher; pass java props for REST port
    # when using burp-rest-api style bridges.
    java_opts = f"-Djava.awt.headless={'true' if use_xvfb or not display else 'false'}"
    env = os.environ.copy()
    env["HACKBOT_BURP_BASE"] = base
    if jar_path:
        env["BURP_REST_API_JAR"] = jar_path

    cmd: list[str]
    if binary.endswith(".jar"):
        java = shutil.which("java") or "java"
        cmd = [java, java_opts, "-jar", binary]
    else:
        cmd = [binary]

    if use_xvfb:
        cmd = ["xvfb-run", "-a", *cmd]

    log_handle = BURP_LOG.open("a", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(BURP_DIR),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        log_handle.close()
        return {
            "ok": False,
            "up": False,
            "error": f"could not start burp: {exc}",
            "command": cmd,
            "jar": jar_info,
        }

    BURP_PID_FILE.write_text(str(proc.pid), encoding="utf-8")
    ui.info(f"burp_ensure: started pid={proc.pid} (log {BURP_LOG})")

    deadline = time.monotonic() + float(wait_sec)
    last_health: dict[str, Any] = {}
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log_handle.close()
            return {
                "ok": False,
                "up": False,
                "started": True,
                "pid": proc.pid,
                "error": f"burp exited early code={proc.returncode}",
                "log": str(BURP_LOG),
                "jar": jar_info,
                "hint": (
                    "Burp may need a one-time GUI accept on this profile. "
                    "Open once on the Kali desktop, then retry burp_ensure."
                ),
            }
        last_health = _burp_already_up(base) or {}
        if last_health.get("up"):
            os.environ["HACKBOT_BURP_BASE"] = last_health.get("base") or base
            log_handle.close()
            return {
                "ok": True,
                "up": True,
                "started": True,
                "pid": proc.pid,
                "base": os.environ["HACKBOT_BURP_BASE"],
                "health": last_health,
                "jar": jar_info,
                "log": str(BURP_LOG),
            }
        time.sleep(2.0)

    log_handle.close()
    # Process may still be up (GUI) without REST — report partial success.
    running = proc.poll() is None
    return {
        "ok": running,
        "up": False,
        "started": True,
        "pid": proc.pid if running else None,
        "base": base,
        "error": "Burp process running but REST control-plane not detected yet",
        "health": last_health,
        "jar": jar_info,
        "log": str(BURP_LOG),
        "hint": (
            "Community often needs the REST extension loaded. "
            "If the GUI is up, Extender → add "
            f"{jar_path or _BURP_REST_JAR_NAME}, set listener 127.0.0.1:1337. "
            "Under YOLO the AI can retry burp_ensure after lab_exec checks the log."
        ),
        "command": cmd,
    }
