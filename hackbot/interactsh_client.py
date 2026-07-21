"""Real Interactsh client (register + authenticated poll + decrypt).

Env:
  HACKBOT_INTERACTSH=1                 — opt into public OAST servers
  HACKBOT_INTERACTSH_SERVER=oast.pro   — comma-separated server hosts
  HACKBOT_INTERACTSH_TOKEN=...         — auth token for protected servers
  HACKBOT_INTERACTSH_SESSION=path.json — persist session (optional)

Legacy Collaborator-style env still works via hackbot.oob (HACKBOT_OOB_*).
Requires the `cryptography` package for register/decrypt.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import string
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

DEFAULT_SERVERS = (
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
)

_SESSION: dict[str, Any] | None = None


def _alphabet(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def interactsh_enabled() -> bool:
    if (os.environ.get("HACKBOT_INTERACTSH") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True
    if (os.environ.get("HACKBOT_INTERACTSH_SERVER") or "").strip():
        return True
    return False


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        return serialization, rsa, padding, hashes, Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "cryptography package required for Interactsh — pip install cryptography"
        ) from exc


def _session_path() -> Path | None:
    raw = (os.environ.get("HACKBOT_INTERACTSH_SESSION") or "").strip()
    if raw:
        return Path(raw)
    return None


def _load_disk_session() -> dict[str, Any] | None:
    path = _session_path()
    if not path or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("correlation_id") and data.get("private_key_pem"):
            return data
    except Exception:  # noqa: BLE001
        return None
    return None


def _save_disk_session(session: dict[str, Any]) -> None:
    path = _session_path()
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # Persist PEM + ids only (needed to poll later)
    blob = {
        "server": session.get("server"),
        "correlation_id": session.get("correlation_id"),
        "secret_key": session.get("secret_key"),
        "private_key_pem": session.get("private_key_pem"),
        "domain": session.get("domain"),
    }
    path.write_text(json.dumps(blob, indent=2), encoding="utf-8")


def _auth_headers() -> dict[str, str]:
    token = (os.environ.get("HACKBOT_INTERACTSH_TOKEN") or os.environ.get("HACKBOT_OOB_AUTH") or "").strip()
    headers = {"User-Agent": "hackbot-interactsh", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token if " " in token else f"Bearer {token}"
    return headers


def _server_list() -> list[str]:
    raw = (os.environ.get("HACKBOT_INTERACTSH_SERVER") or "").strip()
    if raw:
        return [s.strip().removeprefix("https://").removeprefix("http://").rstrip("/") for s in raw.split(",") if s.strip()]
    return list(DEFAULT_SERVERS)


def interactsh_status() -> dict[str, Any]:
    from .oob import oob_configured

    sess = _SESSION or _load_disk_session()
    return {
        "ok": True,
        "interactsh_enabled": interactsh_enabled(),
        "legacy_oob": oob_configured() and not interactsh_enabled(),
        "configured": interactsh_enabled() or oob_configured(),
        "servers": _server_list() if interactsh_enabled() else [],
        "token_set": bool(
            (os.environ.get("HACKBOT_INTERACTSH_TOKEN") or os.environ.get("HACKBOT_OOB_AUTH") or "").strip()
        ),
        "session_active": bool(sess),
        "domain": (sess or {}).get("domain") or "",
        "correlation_id": (sess or {}).get("correlation_id") or "",
        "hint": (
            "Set HACKBOT_INTERACTSH=1 (or HACKBOT_INTERACTSH_SERVER=oast.pro) + pip install cryptography. "
            "Legacy: HACKBOT_OOB_BASE + HACKBOT_OOB_POLL_URL."
        ),
    }


def interactsh_register(*, force_new: bool = False) -> dict[str, Any]:
    """Register with an Interactsh server; returns session + canary-shaped payload."""
    global _SESSION
    if not interactsh_enabled():
        # Fall back to legacy mint when only OOB_BASE is set
        from .oob import mint_canary, oob_configured

        if oob_configured():
            c = mint_canary(kind="interactsh", prefer_interactsh=False)
            return {"ok": True, "mode": "legacy_oob", "canary": c, **interactsh_status()}
        return {"ok": False, "error": "interactsh_disabled", **interactsh_status()}

    if not force_new and _SESSION:
        return {"ok": True, "mode": "interactsh", "session": _public_session(_SESSION), "canary": _canary_from_session(_SESSION)}
    disk = None if force_new else _load_disk_session()
    if disk and disk.get("private_key_pem"):
        _SESSION = disk
        return {
            "ok": True,
            "mode": "interactsh",
            "resumed": True,
            "session": _public_session(disk),
            "canary": _canary_from_session(disk),
        }

    try:
        serialization, rsa, _padding, _hashes, _Cipher, _algorithms, _modes = _crypto()
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc), **interactsh_status()}

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = private_key.public_key()
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Match projectdiscovery PEM type label + PKIX bytes
    b64 = base64.b64encode(pub_der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    pub_pem = ("-----BEGIN RSA PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END RSA PUBLIC KEY-----\n").encode()
    encoded_public_key = base64.b64encode(pub_pem).decode("ascii")
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    correlation_id = _alphabet(20)
    secret_key = str(uuid.uuid4())
    nonce = _alphabet(13)
    headers = _auth_headers()
    last_err = ""
    for server in _server_list():
        body = json.dumps(
            {
                "public-key": encoded_public_key,
                "secret-key": secret_key,
                "correlation-id": correlation_id,
            }
        ).encode("utf-8")
        url = f"https://{server}/register"
        try:
            req = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                raw = resp.read(20_000).decode("utf-8", errors="replace")
            data = json.loads(raw) if raw.strip().startswith("{") else {"message": raw}
            msg = str(data.get("message") or "").lower()
            if data.get("error"):
                last_err = str(data.get("error"))
                continue
            if status >= 400:
                last_err = msg or f"status={status}"
                continue
            if msg and "successful" not in msg and "success" not in msg:
                last_err = msg or "unexpected_register_message"
                continue
            domain = f"{correlation_id}{nonce}.{server}"
            session = {
                "server": server,
                "correlation_id": correlation_id,
                "secret_key": secret_key,
                "private_key_pem": priv_pem,
                "domain": domain,
                "nonce": nonce,
            }
            _SESSION = session
            _save_disk_session(session)
            return {
                "ok": True,
                "mode": "interactsh",
                "session": _public_session(session),
                "canary": _canary_from_session(session),
                **interactsh_status(),
            }
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"
            continue
    return {"ok": False, "error": f"register_failed:{last_err}", **interactsh_status()}


def _public_session(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "server": session.get("server"),
        "correlation_id": session.get("correlation_id"),
        "domain": session.get("domain"),
        "secret_set": bool(session.get("secret_key")),
    }


def _canary_from_session(session: dict[str, Any], *, kind: str = "interactsh") -> dict[str, Any]:
    domain = str(session.get("domain") or "")
    token = str(session.get("correlation_id") or "")[:12]
    http_url = f"https://{domain}/hb"
    xxe_dtd = f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}">]><foo>&xxe;</foo>'
    return {
        "ok": True,
        "kind": kind,
        "token": token,
        "label": f"hb-{kind}-{token}",
        "oob_configured": True,
        "mode": "interactsh",
        "http_url": http_url,
        "dns_host": domain,
        "xss_marker": f"hackbot_oob_{token}",
        "ssrf_payloads": [http_url, f"http://{domain}/", f"https://{domain}/"],
        "xss_payloads": [
            f"<script>fetch('{http_url}')</script>",
            f'"><img src=x onerror=fetch("{http_url}")>',
        ],
        "xxe_payloads": [xxe_dtd],
        "correlation_id": session.get("correlation_id"),
        "server": session.get("server"),
        "hint": "Inject payloads then interactsh_poll / wait_and_poll for DNS/HTTP hits.",
    }


def mint_interactsh_canary(*, kind: str = "ssrf") -> dict[str, Any]:
    """Ensure session + return canary (new nonce subdomain each mint)."""
    global _SESSION
    reg = interactsh_register(force_new=False)
    if not reg.get("ok"):
        return {"ok": False, **reg}
    session = _SESSION or _load_disk_session()
    if not session:
        return {"ok": False, "error": "no_session"}
    # Fresh nonce per canary so hits are distinct, keep same correlation_id
    nonce = _alphabet(13)
    server = session["server"]
    domain = f"{session['correlation_id']}{nonce}.{server}"
    session = {**session, "domain": domain, "nonce": nonce}
    _SESSION = session
    return _canary_from_session(session, kind=kind)


def _decrypt_interaction(private_key_pem: str, aes_key_b64: str, data_b64: str) -> dict[str, Any]:
    serialization, _rsa, padding, hashes, Cipher, algorithms, modes = _crypto()
    private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    aes_key = private_key.decrypt(
        base64.b64decode(aes_key_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    raw = base64.b64decode(data_b64)
    iv, ciphertext = raw[:16], raw[16:]
    # AES-CTR with nonce="" and initial_value=iv (BBOT / interactsh client)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(plain.decode("utf-8", errors="replace"))


def interactsh_poll(canary: dict[str, Any] | None = None, *, wait: bool = True) -> dict[str, Any]:
    """Poll Interactsh session (or legacy oob.poll path)."""
    if interactsh_enabled() or (_SESSION or _load_disk_session()):
        hits = _poll_session()
        if wait and not hits.get("hits"):
            import time

            for _ in range(2):
                time.sleep(2.0)
                hits = _poll_session()
                if hits.get("hits"):
                    break
        return {"ok": True, "canary": canary, **hits}

    from .oob import mint_canary, poll_oob, wait_and_poll

    c = canary or mint_canary(kind="interactsh", prefer_interactsh=False)
    if wait:
        return {"ok": True, "canary": c, **wait_and_poll(c)}
    return {"ok": True, "canary": c, **poll_oob(c)}


def _poll_session() -> dict[str, Any]:
    global _SESSION
    session = _SESSION or _load_disk_session()
    if not session:
        reg = interactsh_register()
        if not reg.get("ok"):
            return {"polled": False, "hits": [], "signal": False, "error": reg.get("error")}
        session = _SESSION or _load_disk_session()
    if not session:
        return {"polled": False, "hits": [], "signal": False, "error": "no_session"}

    server = session["server"]
    cid = session["correlation_id"]
    secret = session["secret_key"]
    url = f"https://{server}/poll?id={urllib.parse.quote(cid)}&secret={urllib.parse.quote(secret)}"
    try:
        req = urllib.request.Request(url, headers=_auth_headers())
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(500_000).decode("utf-8", errors="replace")
        data = json.loads(body) if body.strip().startswith("{") else {}
    except urllib.error.HTTPError as exc:
        err_body = exc.read(2000).decode("utf-8", errors="replace") if exc.fp else ""
        return {
            "polled": True,
            "hits": [],
            "signal": False,
            "error": f"HTTP {exc.code}",
            "preview": err_body[:200],
        }
    except Exception as exc:  # noqa: BLE001
        return {"polled": True, "hits": [], "signal": False, "error": f"{type(exc).__name__}: {exc}"}

    data_list = data.get("data") or []
    aes_key = data.get("aes_key") or ""
    hits: list[dict[str, Any]] = []
    if data_list and aes_key and session.get("private_key_pem"):
        for enc in data_list:
            try:
                item = _decrypt_interaction(session["private_key_pem"], aes_key, enc)
                hits.append(
                    {
                        "protocol": item.get("protocol"),
                        "unique_id": item.get("unique-id") or item.get("full-id"),
                        "remote": item.get("remote-address"),
                        "timestamp": item.get("timestamp"),
                        "preview": str(item.get("raw-request") or "")[:160],
                    }
                )
            except Exception as exc:  # noqa: BLE001
                hits.append({"decrypt_error": type(exc).__name__, "raw_len": len(str(enc))})
    elif data_list:
        # Ciphertext present but no decrypt — still a hit signal
        hits.append({"encrypted_count": len(data_list), "preview": "encrypted interactions present"})

    return {
        "polled": True,
        "hits": hits,
        "signal": bool(hits),
        "count": len(hits),
        "server": server,
        "correlation_id": cid,
    }
