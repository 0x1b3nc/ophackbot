"""Deprecated local web UI — prefer Toad + ``hackbot acp`` (see docs/TOAD.md).

Serves static files and ``POST /api/chat`` as SSE. Kept for compatibility.
"""

from __future__ import annotations

import json
import os
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import ui
from .session import get_active, set_active, status_line
from .turn_bridge import resolve_mode as _resolve_mode
from .turn_bridge import run_bridged_turn as _run_turn
from .yolo import enable_yolo, is_yolo

_PKG_STATIC = Path(__file__).resolve().parent / "web_static"
_ROOT_WEB = Path(__file__).resolve().parents[1] / "web"


def _static_dir() -> Path:
    if (_ROOT_WEB / "index.html").is_file():
        return _ROOT_WEB
    return _PKG_STATIC


STATIC_DIR = _static_dir()


def _msg(role: str, content: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "role": role,
        "content": content,
        "timestamp": int(time.time() * 1000),
    }
    out.update(extra)
    return out


class HackbotHandler(BaseHTTPRequestHandler):
    server_version = "hackbot-ui/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet by default; HACKBOT_UI_VERBOSE=1 for access log
        if os.environ.get("HACKBOT_UI_VERBOSE", "").strip() in {"1", "true", "yes"}:
            super().log_message(fmt, *args)

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/status":
            mode, label = _resolve_mode()
            active = get_active()
            body = {
                "ok": True,
                "mode": mode,
                "label": label,
                "effort": os.environ.get("HACKBOT_EFFORT", "auto"),
                "target": active.name if active else None,
                "hunt": status_line(),
                "yolo": is_yolo(),
            }
            self._json(200, body)
            return
        if path in {"/", "/index.html"}:
            self._file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        # static assets
        rel = path.lstrip("/")
        if ".." in rel or rel.startswith("/"):
            self.send_error(400)
            return
        fp = STATIC_DIR / rel
        if not fp.is_file():
            self.send_error(404)
            return
        ctype = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".ico": "image/x-icon",
        }.get(fp.suffix.lower(), "application/octet-stream")
        self._file(fp, ctype)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        if path == "/api/target":
            name = str(data.get("target") or "").strip()
            if not name:
                self._json(400, {"error": "target required"})
                return
            try:
                sess = set_active(name)
            except FileNotFoundError as exc:
                self._json(404, {"error": str(exc)})
                return
            self._json(200, {"ok": True, "target": sess.name, "hunt": status_line()})
            return

        if path == "/api/provider":
            name = str(data.get("provider") or "").strip().lower()
            if not name:
                self._json(400, {"error": "provider required"})
                return
            os.environ["HACKBOT_PROVIDER"] = name
            mode, label = _resolve_mode()
            self._json(200, {"ok": True, "mode": mode, "label": label})
            return

        if path == "/api/chat":
            prompt = str(data.get("prompt") or "").strip()
            if not prompt:
                self._json(400, {"error": "prompt is required"})
                return
            target = str(data.get("target") or "").strip()
            if target:
                try:
                    set_active(target)
                except FileNotFoundError:
                    pass
            self._sse_chat(prompt)
            return

        self._json(404, {"error": "not found"})

    def _json(self, code: int, obj: dict[str, Any]) -> None:
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse_chat(self, prompt: str) -> None:
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def emit(obj: dict[str, Any]) -> None:
            line = f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode("utf-8")
            self.wfile.write(line)
            self.wfile.flush()

        emit(_msg("user", prompt))
        mode, label = _resolve_mode()
        emit(_msg("status", f"working · {mode}", kind="running"))
        try:
            answer = _run_turn(prompt)
        except Exception as exc:  # noqa: BLE001
            emit(_msg("assistant", f"Error: {type(exc).__name__}: {exc}"))
            emit({"type": "close"})
            return
        emit(_msg("assistant", answer or "(empty)"))
        emit(_msg("status", label, kind="done"))
        emit({"type": "close"})


def start_web_ui(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> int:
    """Run the local UI until Ctrl+C. Returns process exit code."""
    static = _static_dir()
    if not (static / "index.html").is_file():
        ui.error(f"web static missing: {static}")
        return 1
    global STATIC_DIR
    STATIC_DIR = static
    # Web sessions auto-approve (no Confirm in browser); force on with YOLO.
    if not is_yolo():
        enable_yolo()
        ui.warn(
            "web UI enabled YOLO for this process (approve skipped; force on incl. OOS)"
        )
    httpd = ThreadingHTTPServer((host, port), HackbotHandler)
    url = f"http://{host}:{port}/"
    ui.success(f"hackbot ui → {url}")
    ui.info("visual adapted from sossost/claude-hq (MIT) · brains = this kit")
    ui.info("Ctrl+C to stop")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        ui.info("ui stopped")
    finally:
        httpd.server_close()
    return 0
