"""Store redacted evidence under a target directory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .redaction import looks_sensitive, redact_text


class EvidenceStore:
    def __init__(self, target_dir: Path) -> None:
        self.root = target_dir
        self.evidence = target_dir / "evidence"
        self.raw = self.evidence / "raw"
        self.safe = self.evidence / "safe"
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(exist_ok=True)
        self.safe.mkdir(exist_ok=True)

    def save(
        self,
        name: str,
        content: str,
        *,
        keep_raw: bool = False,
    ) -> Path:
        """
        Save evidence. Always writes a redacted copy under evidence/safe/.
        Raw (pre-redaction) is only written when keep_raw=True and lands in
        evidence/raw/ which .gitignore excludes from public repos.
        """
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_name = f"{stamp}_{_safe_filename(name)}"
        redacted = redact_text(content)
        safe_path = self.safe / safe_name
        safe_path.write_text(redacted, encoding="utf-8")
        if keep_raw:
            raw_path = self.raw / safe_name
            raw_path.write_text(content, encoding="utf-8")
        if looks_sensitive(redacted):
            # Still write, but flag for the operator.
            flag = self.safe / f"{safe_name}.SENSITIVE_WARNING"
            flag.write_text(
                "Redaction may be incomplete. Review before sharing or committing.\n",
                encoding="utf-8",
            )
        return safe_path

    def list_safe(self) -> list[Path]:
        return sorted(self.safe.glob("*"))


def _safe_filename(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-._" else "_" for c in name)
    return cleaned[:120] or "evidence.txt"
