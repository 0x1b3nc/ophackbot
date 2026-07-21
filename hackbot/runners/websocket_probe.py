"""Websocket probe — connect, optional send, capture frames (capped)."""

from __future__ import annotations

import json
import ssl
import struct
import hashlib
import base64
import os
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope


def _ws_handshake(host: str, port: int, path: str, *, use_tls: bool, timeout: float) -> tuple[socket.socket, bytes]:
    key = base64.b64encode(os.urandom(16)).decode()
    raw = socket.create_connection((host, port), timeout=timeout)
    sock: socket.socket = raw
    if use_tls:
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
    req = (
        f"GET {path or '/'} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: hackbot-ws-probe\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return sock, data


def _mask_frame(payload: bytes) -> bytes:
    """Client→server text frame with masking (RFC6455)."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    header = bytearray([0x81])  # FIN + text
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    else:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", n))
    return bytes(header) + mask + masked


def websocket_probe(
    target_dir: Path,
    url: str,
    *,
    message: str = "",
    approve: bool = False,
    force: bool = False,
    timeout: float = 8.0,
) -> RunnerResult:
    """Handshake a ws/wss endpoint; optionally send one text frame; read a few bytes."""
    require_in_scope(target_dir, url, action="websocket probe", force=force)
    raw_url = url
    if raw_url.startswith("http://"):
        raw_url = "ws://" + raw_url[len("http://") :]
    elif raw_url.startswith("https://"):
        raw_url = "wss://" + raw_url[len("https://") :]
    elif "://" not in raw_url:
        raw_url = "wss://" + raw_url

    parsed = urlparse(raw_url)
    use_tls = parsed.scheme == "wss"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query

    plan = {
        "url": raw_url,
        "host": host,
        "port": port,
        "message": bool(message),
        "approve": approve,
    }
    ui.code_panel(json.dumps(plan, indent=2), title="websocket_probe", lexer="json")
    cmd = ["websocket_probe", raw_url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    try:
        sock, header = _ws_handshake(host, port, path, use_tls=use_tls, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "signal": False, "error": f"{type(exc).__name__}: {exc}"}
        return RunnerResult(cmd, False, 1, json.dumps(out), "", "error")

    try:
        status_line = header.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        upgraded = b"101" in header.split(b"\r\n", 1)[0] or b"upgrade" in header.lower()
        frames_preview = ""
        if upgraded and message:
            sock.settimeout(timeout)
            sock.sendall(_mask_frame(message.encode()[:500]))
            try:
                frames_preview = sock.recv(2048).decode("utf-8", errors="replace")
            except Exception:
                frames_preview = ""
        signal = upgraded
        reason = "websocket upgrade ok" if upgraded else f"no upgrade: {status_line}"
        out = {
            "ok": True,
            "signal": signal,
            "reason": reason,
            "status_line": status_line,
            "upgraded": upgraded,
            "frame_preview": redact_text(frames_preview[:300]),
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
