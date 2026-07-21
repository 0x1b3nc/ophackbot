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
                    "hint": (
                        "Burp HTTP listener responded. Use export XML/HAR → "
                        "import_burp_xml / import_har for surface seeding. "
                        "Full Burp MCP control plane is not wired yet."
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
