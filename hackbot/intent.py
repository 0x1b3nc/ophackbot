"""Classify prompts so chat stays fast and hunt mode stays thorough."""

from __future__ import annotations

import os
import re

from .providers import normalize_effort

# Pure greetings / meta chat. Keep this tight so real tasks stay in hunt mode.
_CHAT_EXACT = frozenset(
    {
        "hi",
        "hello",
        "hey",
        "yo",
        "ola",
        "olá",
        "oi",
        "obrigado",
        "obrigada",
        "thanks",
        "thank you",
        "thx",
        "valeu",
        "ok",
        "okay",
        "cool",
        "nice",
        "bye",
        "tchau",
        "good morning",
        "good night",
        "bom dia",
        "boa tarde",
        "boa noite",
        "how are you",
        "who are you",
        "what are you",
        "help",
        "?",
    }
)

_CHAT_PREFIXES = (
    "hi ",
    "hello ",
    "hey ",
    "ola ",
    "olá ",
    "oi ",
    "thanks ",
    "thank you",
    "obrigado",
    "obrigada",
)

# Signals that this is a real hunting / tooling task.
_HUNT_RE = re.compile(
    r"(?i)\b("
    r"scope|scopo|in[\s-]?scope|out[\s-]?of[\s-]?scope|"
    r"idor|bola|bac|ssrf|xss|sqli|rce|lfi|graphql|race|"
    r"ddos|dos|brute|bypass|token|credencial|credential|secret|"
    r"ataque|attack|exploit|pentest|hacke|vulnerab|"
    r"nuclei|httpx|katana|ffuf|recon|burp|hexstrike|"
    r"plan|hypothesis|evidence|report|bugcrowd|hackerone|intigriti|"
    r"target|endpoint|fuzz|scan|crawl|probe|"
    r"write|create|edit|delete|append|mkdir|move|"
    r"criar|crie|cria|escreve|escreva|arquivo|"
    r"read_file|SCOPE\.md|PLAN\.md|FINDINGS|"
    r"approve|dry[\s-]?run|campanha|campaign"
    r")\b"
)

_HOST_RE = re.compile(
    r"(?:https?://)?"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
    re.IGNORECASE,
)


def is_chat_prompt(text: str) -> bool:
    """True for greetings / thanks / tiny meta chat. False for hunt work."""
    raw = (text or "").strip()
    if not raw:
        return True
    if raw.startswith("/"):
        return False
    low = raw.lower().rstrip("!.?")
    if low in _CHAT_EXACT:
        return True
    if len(raw) <= 40 and any(low.startswith(p) for p in _CHAT_PREFIXES):
        if _HUNT_RE.search(raw) or _HOST_RE.search(raw):
            return False
        return True
    if len(raw) <= 24 and not _HUNT_RE.search(raw) and not _HOST_RE.search(raw):
        # short freeform with no hunt signal
        if re.fullmatch(r"[\w\sÀ-ÿ'!?.,]+", raw):
            return True
    return False


def is_hunt_prompt(text: str) -> bool:
    return not is_chat_prompt(text)


def resolve_effort_for_prompt(text: str, configured: str | None = None) -> str | None:
    """Pick effort. HACKBOT_EFFORT=auto (or unset defaulting to auto) adapts.

    - auto + chat  -> low
    - auto + hunt  -> medium
    - explicit level -> that level
    """
    raw = configured if configured is not None else os.environ.get("HACKBOT_EFFORT", "auto")
    key = (raw or "auto").strip().lower()
    if key in {"", "auto"}:
        # minimal = almost no extended thinking; keeps "olá" snappy
        return "minimal" if is_chat_prompt(text) else "medium"
    return normalize_effort(key)
