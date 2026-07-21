"""Burp export helpers: parse XML/HAR paths and emit redacted summaries."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..evidence import EvidenceStore
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
        print(msg)
        return RunnerResult([], False, None, "", "", msg)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    lines: list[str] = [f"# Burp summary from {xml_path.name}", ""]
    count = 0
    for item in root.iter("item"):
        if count >= limit:
            lines.append(f"... truncated after {limit} items")
            break
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "").strip()
        status = (item.findtext("status") or "").strip()
        path = (item.findtext("path") or "").strip()
        lines.append(f"- {method} {redact_text(url or path)} status={status}")
        count += 1

    body = "\n".join(lines) + "\n"
    store = EvidenceStore(target_dir)
    saved = store.save("burp_summary.md", body, keep_raw=False)
    print(f"wrote redacted summary: {saved}")
    print(f"items={count}")
    return RunnerResult(
        command=["burp-summarize", str(xml_path)],
        executed=True,
        returncode=0,
        stdout=body,
        stderr="",
        message=str(saved),
    )
