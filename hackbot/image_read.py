"""Read images for bug-bounty context (OCR offline, optional vision model)."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}


def is_image_path(path: Path) -> bool:
    return path.suffix.lower() in IMAGE_SUFFIXES


def read_image(
    path: Path,
    *,
    question: str = "",
    max_ocr_chars: int = 6000,
) -> dict[str, Any]:
    """Describe / OCR an image. Never invent pixels.

    Order:
    1. Metadata always
    2. tesseract OCR if installed (offline)
    3. Optional vision via LLM when a vision-capable provider is configured
    """
    if not path.exists():
        return {"ok": False, "error": "missing", "path": str(path)}
    if not path.is_file():
        return {"ok": False, "error": "not a file", "path": str(path)}
    if not is_image_path(path):
        return {"ok": False, "error": f"not an image suffix: {path.suffix}", "path": str(path)}

    size = path.stat().st_size
    meta = {
        "ok": True,
        "path": str(path),
        "suffix": path.suffix.lower(),
        "bytes": size,
        "question": question or "",
    }

    ocr_text = _tesseract_ocr(path)
    if ocr_text is not None:
        meta["ocr"] = ocr_text[:max_ocr_chars]
        meta["ocr_truncated"] = len(ocr_text) > max_ocr_chars
        meta["source"] = "tesseract"

    vision = _vision_describe(path, question=question or "Extract all visible text and UI labels relevant to bug bounty hunting.")
    if vision:
        meta["vision"] = vision.get("text") or ""
        meta["vision_provider"] = vision.get("provider")
        meta["source"] = "vision" if not ocr_text else "tesseract+vision"

    if not ocr_text and not vision:
        meta["message"] = (
            "Image opened (metadata only). Install tesseract for offline OCR, "
            "or configure a vision-capable model (/provider) so I can describe it."
        )
        meta["source"] = "metadata"
        # Small preview as data-uri hint for operators wiring UIs (not logged as secret)
        if size <= 400_000:
            raw = path.read_bytes()
            meta["base64_preview"] = base64.b64encode(raw[:12000]).decode("ascii")
            meta["base64_preview_note"] = "truncated base64 prefix only"

    return meta


def _tesseract_ocr(path: Path) -> str | None:
    if not shutil.which("tesseract"):
        return None
    try:
        completed = subprocess.run(
            ["tesseract", str(path), "stdout", "-l", "eng+por"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or "").strip()
    return text or None


def _vision_describe(path: Path, *, question: str) -> dict[str, str] | None:
    """Optional vision path — disabled unless HACKBOT_VISION=1 and a model is set.

    Full multimodal wire varies by provider; OCR (tesseract) is the reliable offline path.
    """
    import os

    if os.environ.get("HACKBOT_VISION", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    try:
        from .llm import LLMError, chat
        from .providers import resolve_config
    except Exception:
        return None
    try:
        cfg = resolve_config()
    except Exception:
        return None
    if cfg.provider in {"offline", "codex"}:
        return None
    try:
        resp = chat(
            system=(
                "You help with authorized bug bounty. The operator named an image path "
                "but binary pixels may not be attached. If you cannot see the image, say so."
            ),
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"{question}\n\nImage path: {path}\n"
                        f"Size bytes: {path.stat().st_size}. "
                        "If vision input is unsupported, reply exactly: NO_VISION"
                    ),
                }
            ],
            tools=[],
        )
        text = (resp.text or "").strip()
        if not text or text == "NO_VISION":
            return None
        return {"text": text[:8000], "provider": cfg.provider}
    except (LLMError, Exception):
        return None
