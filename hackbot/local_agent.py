"""Offline agent: read the prompt, decide by rules, run tools. No LLM needed.

This is the "brain-lite" path. It cannot free-form reason, but it can:
  - read a plain-language task
  - pull out the host / target folder / bug class / tool / platform
  - open study notes + executable playbooks
  - build an ordered plan of concrete tool calls
  - execute each one (dry-run first; active traffic still needs --approve)

Everything routes through the same tools the LLM agent uses, so the safety
rails (scope check, redaction, approve gate, /force) are identical.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import ui
from .campaign import has_attack_intent, is_campaign_prompt
from .force import disable_force, enable_force, is_forced, prompt_wants_force
from .identity import load_identity
from .intent import is_chat_prompt
from .knowledge import classify
from .playbooks import playbook_for
from .prompt_router import RouteDecision, route_prompt
from .session import get_active
from .session_import import extract_path_mentions
from .tools import ROOT, TARGETS, execute_tool

_AUTHZ_CLASSES = frozenset(
    {"idor", "bola", "bac", "bfla", "authz", "ssrf", "race", "rate-limit", "dos", "stress"}
)

ApproveFn = Callable[[str], bool]

TOOL_NAMES = (
    "httpx",
    "katana",
    "nuclei",
    "ffuf",
    "reconftw",
    "hexstrike",
    "burp",
    "rate_probe",
)

PLATFORM_ALIASES = {
    "bugcrowd": "bugcrowd",
    "hackerone": "hackerone",
    "h1": "hackerone",
    "intigriti": "intigriti",
    "yeswehack": "yeswehack",
    "ywh": "yeswehack",
    "synack": "synack",
    "immunefi": "immunefi",
    "yogosha": "yogosha",
    "generic": "generic",
    "agnostic": "generic",
    "universal": "generic",
}

APPROVE_WORDS = (
    "--approve",
    "approve",
    "for real",
    "actually run",
    "execute it",
    "send traffic",
    "real traffic",
)

# Extract host (+ optional path) or full URL. Requires a dot + TLD so
# "targets/demo" and bare words never match.
_TARGET_RE = re.compile(
    r"(?:https?://)?"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    r"(?::\d+)?"
    r"(?:/[^\s'\"]*)?",
    re.IGNORECASE,
)

# Tokens that look like a domain but are really filenames.
_FILE_SUFFIXES = (".md", ".txt", ".py", ".json", ".xml", ".har", ".yaml", ".yml", ".png", ".jpg")


@dataclass
class Action:
    thought: str
    tool: str
    args: dict[str, Any]


@dataclass
class Interpretation:
    target_dir: str
    full_target: str | None
    host: str | None
    classes: list[str]
    tool: str | None
    platform: str | None
    approve: bool
    force: bool
    intents: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def _known_targets() -> list[str]:
    if not TARGETS.exists():
        return []
    return sorted(
        p.name for p in TARGETS.iterdir() if p.is_dir() and p.name != "__pycache__"
    )


def _detect_target_dir(text: str) -> str:
    low = text.lower()
    m = re.search(r"targets[/\\]([a-z0-9._-]+)", low)
    if m:
        return f"targets/{m.group(1)}"
    known = _known_targets()
    for name in known:
        if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", low):
            return f"targets/{name}"
    active = get_active()
    if active:
        return f"targets/{active.name}"
    if "demo" in known:
        return "targets/demo"
    return "targets/demo"


def _detect_targets(text: str) -> tuple[str | None, str | None]:
    """Return (full_match, host) from the prompt, or session fallback."""
    for m in _TARGET_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:)")
        low = raw.lower()
        if any(low.endswith(suf) for suf in _FILE_SUFFIXES):
            continue
        host = raw
        if "://" in host:
            from urllib.parse import urlparse

            host = urlparse(host).hostname or host
        host = host.split("/")[0].split(":")[0]
        return raw, host.lower()
    active = get_active()
    if active and active.in_scope_hosts:
        h = active.in_scope_hosts[0]
        # Strip wildcard prefix for a usable host hint
        if h.startswith("*."):
            return None, None
        return h, h
    return None, None


def _detect_tool(text: str) -> str | None:
    low = text.lower()
    if any(w in low for w in ("rate_probe", "rate-probe", "rate probe")):
        return "rate_probe"
    if re.search(r"\bdos\b", low) or "stress test" in low or "rate-limit" in low or "rate limit" in low:
        return "rate_probe"
    for name in TOOL_NAMES:
        if name in low:
            return name
    return None


def _detect_platform(text: str) -> str | None:
    low = text.lower()
    # Prefer longer aliases; short ones (h1, ywh) need word boundaries.
    for alias, canon in sorted(PLATFORM_ALIASES.items(), key=lambda x: -len(x[0])):
        if len(alias) <= 3:
            if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", low):
                return canon
        elif alias in low:
            return canon
    return None


def _wants(text: str, *words: str) -> bool:
    low = text.lower()
    return any(w in low for w in words)


_FOLDER_ALIASES = {
    "downloads": "Downloads",
    "download": "Downloads",
    "desktop": "Desktop",
    "documentos": "Documents",
    "documents": "Documents",
    "docs": "Documents",
}


def _folder_from_text(text: str) -> Path | None:
    low = text.lower()
    for key, canon in _FOLDER_ALIASES.items():
        if re.search(rf"(?i)\b{re.escape(key)}\b", low):
            return Path.home() / canon
    return None


def _with_default_suffix(name: str, text: str) -> str:
    if Path(name).suffix:
        return name
    ext_m = re.search(r"(?i)(\.(?:md|txt|yaml|yml|json|csv))\b", text)
    return name + (ext_m.group(1) if ext_m else ".md")


def _parse_create_file_path(text: str) -> str | None:
    """Parse PT/EN 'create file in Downloads named X' into an absolute path."""
    # Absolute / home-relative path already in the prompt
    m = re.search(
        r"(?i)(?:arquivo|file)\s+[\"']?((?:[A-Za-z]:\\|\\\\|~/|/)[^\s\"']+)[\"']?",
        text,
    )
    if m:
        return str(Path(m.group(1)).expanduser())

    m = re.search(
        r"(?i)(?:create|write|cria(?:r)?|crie|escrev[ea]|salva(?:r)?|save)\s+"
        r"(?:(?:um|a|the)\s+)?(?:arquivo|file)\s+[\"']?([^\s\"']+\.\w{1,8})[\"']?",
        text,
    )
    if m and ("/" in m.group(1) or "\\" in m.group(1)):
        return str(Path(m.group(1)).expanduser())

    folder_pat = r"(?:pasta|folder|dir(?:ectory)?)\s+(?:de\s+|do\s+|da\s+|the\s+)?[\"']?([^\s\"']+)[\"']?"
    name_pat = r"(?:chamado|chamada|named|called|name(?:d)?)\s+[\"']?([^\s\"']+)[\"']?"

    # "... na pasta Downloads chamado scope.md"
    m = re.search(rf"(?i){folder_pat}.*?{name_pat}", text)
    if m:
        folder_raw, name = m.group(1), m.group(2)
        folder_key = folder_raw.strip().rstrip("/\\").lower()
        if name.lower() in {"arquivo", "file"}:
            return None
        name = _with_default_suffix(name, text)
        if folder_key in _FOLDER_ALIASES:
            base = Path.home() / _FOLDER_ALIASES[folder_key]
        elif Path(folder_raw).is_absolute():
            base = Path(folder_raw)
        else:
            base = Path.home() / folder_raw
        return str((base / name).expanduser())

    # "... chamado scopetest na pasta de downloads" / "um .md chamado X … downloads"
    m = re.search(rf"(?i){name_pat}.*?{folder_pat}", text)
    if m:
        name, folder_raw = m.group(1), m.group(2)
        if name.lower() not in {"arquivo", "file"}:
            name = _with_default_suffix(name, text)
            folder_key = folder_raw.strip().rstrip("/\\").lower()
            if folder_key in _FOLDER_ALIASES:
                return str(Path.home() / _FOLDER_ALIASES[folder_key] / name)
            base = Path(folder_raw) if Path(folder_raw).is_absolute() else Path.home() / folder_raw
            return str(base / name)

    # named file + known folder word anywhere (order-free)
    m = re.search(rf"(?i){name_pat}", text)
    folder = _folder_from_text(text)
    if m and folder is not None:
        name = m.group(1)
        if name.lower() not in {"arquivo", "file", "pasta", "folder"}:
            return str(folder / _with_default_suffix(name, text))

    # "create scope.md in Downloads" / "cria scope.md em Downloads"
    m = re.search(
        r"(?i)(?:arquivo|file)\s+[\"']?([^\s\"']+\.\w{1,8})[\"']?"
        r".*?(?:(?:na|em|in|into)\s+(?:pasta\s+(?:de\s+|do\s+|da\s+)?|folder\s+)?)[\"']?([^\s\"']+)[\"']?",
        text,
    )
    if m:
        name, folder_raw = m.group(1), m.group(2)
        folder_key = folder_raw.strip().rstrip("/\\").lower()
        if folder_key in _FOLDER_ALIASES:
            return str(Path.home() / _FOLDER_ALIASES[folder_key] / name)
        return str((Path(folder_raw).expanduser() / name))

    m = re.search(
        r"(?i)[\"']?([A-Za-z0-9_.-]+\.(?:md|txt|yaml|yml|json|csv))[\"']?"
        r".*?(?:downloads|desktop|documentos|documents)",
        text,
    )
    if m:
        folder = _folder_from_text(text)
        if folder is not None:
            return str(folder / m.group(1))

    m = re.search(
        r"(?i)(?:downloads|desktop|documentos|documents).*?"
        r"[\"']?([A-Za-z0-9_.-]+\.(?:md|txt|yaml|yml|json|csv))[\"']?",
        text,
    )
    if m:
        folder = _folder_from_text(text)
        if folder is not None:
            return str(folder / m.group(1))

    return None


def _default_new_file_content(path: str) -> str:
    name = Path(path).name
    if name.lower() == "scope.md":
        return (
            "# Scope\n\n"
            "_Created by hackbot. Fill in-scope hosts, out-of-scope, and rules._\n\n"
            "## In scope\n\n- \n\n"
            "## Out of scope\n\n- \n\n"
            "## Notes\n\n"
        )
    if Path(path).suffix.lower() in {".md", ".txt"}:
        return f"# {Path(path).stem}\n\n"
    return ""


def _parse_file_content(text: str) -> str | None:
    """Pull explicit file body from NL ('com o texto', content:, triple quotes)."""
    m = re.search(r'(?is)(?:```|""")\s*(.*?)\s*(?:```|""")', text)
    if m and m.group(1).strip():
        return m.group(1).strip()
    m = re.search(
        r"(?is)(?:com\s+o\s+texto|escrevendo|content)\s*[:=]\s*[\"'](.+?)[\"']\s*$",
        text,
    )
    if m and m.group(1).strip():
        return m.group(1).strip()
    m = re.search(
        r"(?is)(?:com\s+o\s+texto|escrevendo|content)\s*[:=]\s*(.+)$",
        text,
    )
    if m and m.group(1).strip():
        body = m.group(1).strip().strip("\"'")
        if body and len(body) < 20_000:
            return body
    m = re.search(r"(?is)\b(?:dizendo|saying)\s+[\"'](.+?)[\"']\s*$", text)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return None


def _parse_edit_replace(text: str) -> tuple[str, str] | None:
    """Parse 'troca X por Y' / 'replace X with Y' → (old, new)."""
    m = re.search(
        r"(?is)(?:troca|substitu[ia]|replace)\s+[\"'](.+?)[\"']\s+"
        r"(?:por|with|by|para)\s+[\"'](.+?)[\"']",
        text,
    )
    if m:
        return m.group(1), m.group(2)
    m = re.search(
        r"(?is)(?:troca|substitu[ia]|replace)\s+(\S+)\s+(?:por|with|by|para)\s+(\S+)",
        text,
    )
    if m:
        return m.group(1), m.group(2)
    return None


def _parse_set_account(text: str) -> dict[str, str] | None:
    """Extract account slot + username/email + password from NL."""
    name = ""
    # Require whitespace so "accounts.yaml" does not become name="s"
    m_name = re.search(
        r"(?i)\b(?:conta|account)\s+([A-Za-z0-9_-]{1,12})\b",
        text,
    )
    if m_name:
        name = m_name.group(1)
    if not name:
        # Standalone A/B only (not the local-part of an email like a@x.com)
        m_ab = re.search(r"(?i)\b(?:accounts?\.ya?ml).*?\b([AB])\b(?!@)", text)
        if m_ab:
            name = m_ab.group(1).upper()
        elif re.search(r"(?i)\baccounts?\.ya?ml\b", text):
            name = "A"
    if not name:
        return None
    if name.upper() in {"A", "B"}:
        name = name.upper()

    username = ""
    password = ""
    m_email = re.search(
        r"(?i)(?:e-?mail|username|usu[aá]rio|user)\s*[:=]?\s*"
        r"([^\s\"']+@[^\s\"']+|[^\s\"']+)",
        text,
    )
    if m_email:
        username = m_email.group(1).strip(".,;")
    if not username:
        m_bare = re.search(r"(?i)\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text)
        if m_bare:
            username = m_bare.group(1)

    m_pass = re.search(
        r"(?i)(?:senha|password|pass|pwd)\s*[:=]?\s*[\"']?([^\s\"']+)[\"']?",
        text,
    )
    if m_pass:
        password = m_pass.group(1).strip(".,;")

    if not username and not password:
        return None
    return {"name": name, "username": username, "password": password}


def _wants_set_account(text: str) -> bool:
    """True when operator is writing login creds — not bare 'login com accounts.yaml'."""
    has_cred_value = bool(
        re.search(r"(?i)(?:senha|password|pass|pwd)\s*[:=]?\s*\S+", text)
        or re.search(r"(?i)(?:e-?mail|username|usu[aá]rio|user)\s*[:=]?\s*\S+", text)
        or re.search(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text)
    )
    if not has_cred_value:
        return False
    write_hint = _wants(
        text,
        "coloca",
        "coloque",
        "altera",
        "alterar",
        "set account",
        "set_account",
        "grava",
        "gravar",
        "update account",
        "accounts.yaml",
        "accounts.yml",
        "conta a",
        "conta b",
        "account a",
        "account b",
    ) or bool(re.search(r"(?i)\b(?:conta|account)\s+[AB]\b", text))
    return write_hint


def _hosts_from_text(blob: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(
        r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
        blob or "",
    ):
        h = m.group(1).lower().rstrip(".")
        if h in seen or h.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif")):
            continue
        if h in {"example.com", "localhost.localdomain"}:
            continue
        seen.add(h)
        hosts.append(h)
        if len(hosts) >= 12:
            break
    return hosts


def interpret(text: str) -> Interpretation:
    full_target, host = _detect_targets(text)
    tool = _detect_tool(text)
    platform = _detect_platform(text)
    classes = classify(text)
    approve = _wants(text, *APPROVE_WORDS)
    force = is_forced() or prompt_wants_force(text)

    intents: list[str] = []
    if _wants(text, "list target", "which target", "what target", "show target"):
        intents.append("list")
    # Avoid treating "scope.md" / "criar arquivo … scope" as a SCOPE check
    if _wants(text, "in-scope", "in scope", "out of scope", "out-of-scope", "is it ok") or (
        _wants(text, "scope", "allowed")
        and not _wants(text, "scope.md", "arquivo", "file", "crie", "cria", "criar", "create")
    ):
        intents.append("scope")
    if _wants(
        text,
        "note",
        "notes",
        "study",
        "knowledge",
        "learn",
        "playbook",
        "read up",
        "how do i test",
        "how to test",
    ):
        intents.append("knowledge")
    if _wants(text, "plan", "hypothesis", "approach", "strategy"):
        intents.append("plan")
    # Attack / hunt → executable playbook (dry-run by default)
    if _wants(
        text,
        "hunt",
        "hunting",
        "caça",
        "caca",
        "caçar",
        "cacar",
        "test for",
        "attack",
        "exploit",
        "run playbook",
        "execute playbook",
    ):
        intents.append("playbook_run")
    if tool or _wants(text, "run", "dry-run", "dry run", "scan", "probe", "crawl", "fuzz", "recon"):
        intents.append("run")
    if platform or _wants(text, "report", "write-up", "writeup", "write up", "submit"):
        intents.append("report")
    if _wants(text, "redact"):
        intents.append("redact")
    if _wants(text, "read ", "show me", "open the", "context", "abre o", "abre a", "leia ", "ler "):
        intents.append("read")
    # Accounts (login email/password) before sessions (bearer/cookie)
    if _wants_set_account(text):
        intents.append("set_account")
    # Sessions: slash commands are optional — NL + file paths are first-class
    if _wants(
        text,
        "set session",
        "session a",
        "session b",
        "/session",
        "credencial",
        "credenciais",
        "credentials",
        "tokens estão",
        "tokens estao",
        "tokens are",
        "bearer",
        "cookie",
        "sessions.yaml",
        "arquivo com",
        "file with",
        "load session",
        "carregar session",
        "carregar sessao",
        "carregar sessão",
        "import session",
        "importar session",
        "conta a",
        "conta b",
        "account a",
        "account b",
    ) and "set_account" not in intents:
        intents.append("set_session")
    if _wants(
        text,
        "show identity",
        "show session",
        "/sessions",
        "which sessions",
        "quais sessoes",
        "quais sessões",
    ):
        intents.append("show_identity")
    if _wants(
        text,
        "imagem",
        "image",
        "screenshot",
        "print ",
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        "leia a imagem",
        "read the image",
        "ocr",
    ):
        intents.append("read_image")
    if _wants(
        text,
        "extrai o conteudo",
        "extrai o conteúdo",
        "extraia o conteudo",
        "extraia o conteúdo",
        "extrair conteudo",
        "extrair conteúdo",
        "extract page",
        "extract the page",
        "resume a pagina",
        "resume a página",
        "resumir a pagina",
        "resumir a página",
        "pega o texto da pagina",
        "pega o texto da página",
        "scrape the page",
    ):
        intents.append("extract_page")
    if _wants(text, ".har", "har file", "arquivo har", "burp export", "proxy history", "import har"):
        intents.append("import_har")
    if _wants(text, "jwt", "json web token", "decode jwt", "analisa jwt", "analyze jwt"):
        intents.append("analyze_jwt")
    if _wants(text, ".js", "javascript", "bundle", "analyze js", "analisa o js", "endpoints no js"):
        intents.append("analyze_js")
    if _wants(text, "graphql", "introspection"):
        intents.append("graphql")
    if _wants(text, "cors", "cross-origin", "access-control-allow"):
        intents.append("cors")
    if _wants(text, "open redirect", "openredirect", "redirect aberto", "unvalidated redirect"):
        intents.append("open_redirect")
    if _wants(text, "param min", "mine param", "hidden param", "arjun", "parametros escondidos", "parâmetros escondidos"):
        intents.append("mine_params")
    if _wants(text, "crt.sh", "subdomain", "subdominio", "subdomínio", "certificate transparency"):
        intents.append("crt")
    if _wants(text, "wayback", "arquivo morto", "historical url", "urls antigas"):
        intents.append("wayback")
    # Create/write file (PT-BR + EN) — must win over bare "na pasta" list_dir
    if _wants(
        text,
        "crie um arquivo",
        "cria um arquivo",
        "criar arquivo",
        "create a file",
        "create file",
        "write a file",
        "write file",
        "escreve um arquivo",
        "escreva um arquivo",
        "salva um arquivo",
        "save a file",
        "gera um arquivo",
        "make a file",
        "novo arquivo",
        "new file",
    ) or (
        _wants(text, "crie", "cria", "criar", "create", "escreve", "escreva", "write")
        and _wants(text, "arquivo", "file", ".md", ".txt", ".yaml", ".yml", ".json")
        and not _wants(text, "credencial", "credentials", "tokens", "sessions.yaml")
    ):
        intents.append("write_file")
    if _wants(
        text,
        "lista a pasta",
        "listar pasta",
        "list dir",
        "list folder",
        "o que tem na pasta",
        "what's in the folder",
        "conteudo da pasta",
        "conteúdo da pasta",
    ) or (
        _wants(text, "na pasta")
        and not _wants(text, "crie", "cria", "criar", "create", "escreve", "write", "arquivo chamado", "file called")
    ):
        intents.append("list_dir")
    if _wants(text, "security header", "headers de seguranca", "headers de segurança", "analyze headers"):
        intents.append("analyze_headers")
    if _wants(text, "lfi", "path traversal", "path-traversal", "/etc/passwd", "local file"):
        intents.append("lfi")
    if _wants(text, "ssti", "template injection", "{{7*7}}", "jinja", "freemarker"):
        intents.append("ssti")
    if _wants(text, "xxe", "xml external", "external entity"):
        intents.append("xxe")
    if _wants(
        text,
        "bootstrap session",
        "session bootstrap",
        "faz login",
        "fazer login",
        "accounts.yaml",
        "usa accounts",
        "login com accounts",
        "autentica a/b",
    ) and "set_account" not in intents:
        intents.append("session_bootstrap")
    if _wants(
        text,
        "detecta login",
        "detectar login",
        "detect login",
        "find login",
        "acha o login",
        "onde e o login",
        "onde é o login",
        "login surface",
        "superficie de login",
        "superfície de login",
    ):
        intents.append("detect_login")
    if _wants(
        text,
        "testa sessao",
        "testa sessão",
        "testar sessao",
        "testar sessão",
        "session smoke",
        "whoami",
        "verifica sessao",
        "verifica sessão",
        "smoke session",
        "test session",
    ):
        intents.append("session_smoke")
    if _wants(
        text,
        "captura sessao",
        "captura sessão",
        "capturar sessao",
        "capturar sessão",
        "capture session",
        "browser capture",
        "abre o browser pro login",
        "abre browser pro login",
        "idp capture",
        "sso capture",
        "login no browser",
    ):
        intents.append("idp_capture")
    if _wants(text, "ssrf", "server-side request", "metadata.google", "169.254.169.254"):
        intents.append("ssrf")
    if _wants(
        text,
        "idor probe",
        "probe idor",
        "ownership swap",
        "a/b idor",
        "idor a/b",
        "bola probe",
        "testa idor",
        "testar idor",
        "authz probe",
    ):
        intents.append("idor_probe")
    if _wants(
        text,
        "discover paths",
        "content discovery",
        "path fuzz",
        "fuzz paths",
        "dirbust",
        "descobrir paths",
        "descobrir rotas",
        "content fuzz",
    ):
        intents.append("discover_paths")
    if _wants(
        text,
        "oob canary",
        "oob mint",
        "blind canary",
        "collaborator",
        "interactsh",
        "mint canary",
        "canary oob",
    ):
        intents.append("oob")
    if _wants(text, "interactsh poll", "oob poll", "poll canary", "poll oob"):
        intents.append("oob_poll")
    if _wants(
        text,
        "hunt checklist",
        "checklist hunt",
        "pre-hunt",
        "prehunt",
        "checklist do hunt",
    ):
        intents.append("hunt_checklist")
    if _wants(text, "pause hunt", "pausar hunt", "hunt pause"):
        intents.append("hunt_pause")
    if _wants(
        text,
        "resume hunt",
        "retomar hunt",
        "unpause hunt",
        "retoma o hunt",
        "continua o hunt",
        "continuar hunt",
        "resume the hunt",
    ):
        intents.append("hunt_resume")
    if _wants(text, "hunt telemetry", "telemetria hunt", "hunt stats"):
        intents.append("hunt_telemetry")
    if _wants(text, "cdp attach", "chrome debugging", "remote debugging", "cdp_attach"):
        intents.append("cdp")
    if _wants(text, "mass assignment", "mass-assignment", "isAdmin true", "role admin json"):
        intents.append("mass_assignment")
    if _wants(text, "method override", "x-http-method-override", "method-override"):
        intents.append("method_override")
    if _wants(text, "parameter pollution", "hpp", "http parameter pollution"):
        intents.append("hpp")
    if _wants(text, "submit ready", "pronto pra submit", "ready to submit"):
        intents.append("submit_ready")
    if _wants(text, "race condition", "race cond", "toctou", "parallel burst", "condicao de corrida", "condição de corrida"):
        intents.append("race")
    if _wants(text, "websocket", "websockets", "wss://", "ws://"):
        intents.append("websocket")
    if _wants(text, "mobsf", "mobile security framework"):
        intents.append("mobsf")
    if _wants(text, "frida", "objection", "ssl unpin", "unpinning"):
        intents.append("frida")
    if _wants(text, "oauth", "authorize?", "openid", "/oauth/"):
        intents.append("oauth")

    if _wants(text, "jwt active", "alg=none", "forge jwt", "jwt bypass"):
        intents.append("jwt_active")
    if _wants(text, "chain", "encadear", "exploit chain", "build chain", "cadeia"):
        intents.append("build_chains")
    # Target folder / filesystem helpers (PT-BR + EN)
    if _wants(
        text,
        "set target",
        "usa o target",
        "use o target",
        "troca pro target",
        "trocar target",
        "ativa o target",
        "ativar target",
        "load target",
        "carrega o target",
        "carregar target",
        "/target",
    ) or (
        _wants(text, "target")
        and _wants(text, "demo", "targets/", "pasta do programa", "programa ")
        and not _wants(text, "list target", "which target", "what target")
    ):
        intents.append("set_target")
    if _wants(
        text,
        "cria uma pasta",
        "criar pasta",
        "create folder",
        "create directory",
        "mkdir",
        "make dir",
        "make folder",
        "nova pasta",
    ):
        intents.append("make_dir")
    if _wants(
        text,
        "apaga o arquivo",
        "apagar arquivo",
        "delete file",
        "delete the file",
        "remove o arquivo",
        "remover arquivo",
        "rm ",
    ) and not _wants(text, "crie", "cria", "criar", "create"):
        intents.append("delete_path")
    if _wants(
        text,
        "edita o arquivo",
        "editar arquivo",
        "edit file",
        "edit the file",
        "altera o arquivo",
        "patch the file",
    ):
        intents.append("edit_file")
    if _wants(
        text,
        "map surface",
        "mapear surface",
        "mapeia a surface",
        "map the surface",
        "surface map",
        "recon surface",
        "mapa de superficie",
        "mapa de superfície",
    ):
        intents.append("map_surface")
    if _wants(
        text,
        "http request",
        "faz um get",
        "faz um post",
        "mande um get",
        "send a get",
        "send a post",
        "curl ",
        "request http",
    ):
        intents.append("http_request")
    if _wants(text, "burp replay", "replay burp", "burp send", "repeater", "replay history"):
        intents.append("burp_replay")
    if _wants(text, "frida", "mobile", "apk", "objection", "mobsf", "adb"):
        intents.append("mobile")
    if _wants(
        text,
        "mobile bridge",
        "apk e har",
        "apk and har",
        "pipeline mobile",
        "bridge mobile",
        "do apk pro hunt",
        "do har pro hunt",
    ):
        intents.append("mobile_bridge")
    if _wants(
        text,
        "com sessao",
        "com sessão",
        "with session",
        "browser session",
        "abre autenticado",
        "open authenticated",
        "inject session",
        "usa sessao",
        "usa sessão",
        "session a",
        "session b",
        "sessao a",
        "sessão a",
        "sessao b",
        "sessão b",
    ):
        intents.append("browser_session")
    if _wants(
        text,
        "diff session",
        "diff a/b",
        "diff a b",
        "compara sessao",
        "compara sessão",
        "compare session",
        "a vs b",
        "a versus b",
        "idor browser",
        "browser idor",
    ):
        intents.append("browser_diff")
    if _wants(
        text,
        "cookies",
        "cookie jar",
        "lista cookies",
        "list cookies",
        "ver cookies",
    ):
        intents.append("browser_cookies")
    if _wants(
        text,
        "localstorage",
        "sessionstorage",
        "local storage",
        "session storage",
        "web storage",
        "storage do browser",
    ):
        intents.append("browser_storage")
    if _wants(
        text,
        "network capture",
        "capture requests",
        "captura rede",
        "captura de rede",
        "xhr",
        "browser network",
        "traffic no browser",
    ):
        intents.append("browser_network")
    if _wants(
        text,
        "browser",
        "playwright",
        "cdp",
        "puppeteer",
        "selenium",
        "screenshot",
        "abre no browser",
        "open in browser",
        "tire um print",
    ):
        intents.append("browser")
    if _wants(text, "burp.xml", "burp xml", "export burp", "import burp", ".xml"):
        # only if burp-ish
        if _wants(text, "burp", "proxy", "export"):
            intents.append("import_burp")
    if _wants(text, "burp rest", "burp mcp", "burp api", "burp running"):
        intents.append("burp_rest")
    if _wants(
        text,
        "sobe o burp",
        "sobe burp",
        "start burp",
        "burp_ensure",
        "ensure burp",
        "liga o burp",
        "open burp",
        "abre o burp",
    ):
        intents.append("burp_ensure")
    if _wants(
        text,
        "stack_prepare",
        "arruma gau",
        "fix gau",
        "arruma go",
        "fix go path",
        "conserta gau",
        "prepare stack",
        "arruma o path",
    ):
        intents.append("stack_prepare")
    if _wants(text, "lab_exec", "roda sudo", "com sudo", "apt install"):
        intents.append("lab_exec")
    if _wants(text, "o que funcionou", "what worked", "learn suggest", "tecnicas", "técnicas anteriores"):
        intents.append("learn_suggest")
    if is_campaign_prompt(text) or has_attack_intent(text):
        intents.append("campaign")
    # Bare "hunt this" without slash — still campaign/hunt
    if _wants(text, "go hunt", "start hunting", "comeca a cacar", "começa a caçar", "cacada", "caçada"):
        if "campaign" not in intents:
            intents.append("campaign")

    # Single-class hunt still works when not treated as full campaign
    if "campaign" not in intents and any(
        c in _AUTHZ_CLASSES
        or c in ("rate-limit", "dos", "stress", "race", "brute", "secrets", "auth-bypass")
        for c in classes
    ):
        if "playbook_run" not in intents and _wants(
            text, "test", "check", "try", "do ", "attack", "hunt"
        ):
            intents.append("playbook_run")

    return Interpretation(
        target_dir=_detect_target_dir(text),
        full_target=full_target,
        host=host,
        classes=classes,
        tool=tool,
        platform=platform,
        approve=approve,
        force=force,
        intents=intents,
    )


# ---------------------------------------------------------------------------
# planning: interpretation -> ordered tool calls
# ---------------------------------------------------------------------------

def _primary_class(classes: list[str]) -> str:
    pb = playbook_for(" ".join(classes) if classes else "recon")
    return pb.class_name


def build_plan(text: str, interp: Interpretation) -> list[Action]:
    plan: list[Action] = []
    intents = interp.intents
    host = interp.host
    target = interp.full_target or host or ""
    cls = _primary_class(interp.classes)

    if "list" in intents:
        plan.append(Action("List the target folders I know about.", "list_targets", {}))

    if "write_file" in intents:
        path = _parse_create_file_path(text)
        if path:
            content = _parse_file_content(text) or _default_new_file_content(path)
            plan.append(
                Action(
                    f"Criar arquivo `{path}` (pede approve antes de gravar).",
                    "write_file",
                    {"path": path, "content": content},
                )
            )
        else:
            plan.append(
                Action(
                    "Preciso do caminho + nome do arquivo.",
                    "_note",
                    {
                        "message": (
                            "ex: crie um arquivo na pasta Downloads chamado scope.md\n"
                            "ou: create file C:/Users/me/Downloads/notes.txt\n"
                            "com conteúdo: com o texto: ..."
                        )
                    },
                )
            )
        # Pure create-file turns stop here. If they also asked to hunt/recon,
        # keep planning so we don't stall after the approve on write_file.
        follow_on = set(intents) - {
            "write_file",
            "edit_file",
            "make_dir",
            "delete_path",
            "list",
            "list_dir",
            "read",
        }
        if not follow_on:
            return plan

    if "set_target" in intents:
        tdir = interp.target_dir or ""
        name = ""
        if tdir and tdir not in {"targets", "targets/"}:
            name = tdir.replace("\\", "/").rstrip("/").split("/")[-1]
        if not name:
            m = re.search(r"(?i)\btargets[/\\]([a-z0-9_-]+)\b", text)
            if m:
                name = m.group(1)
        if not name:
            m = re.search(
                r"(?i)\b(?:target|programa)\s+([a-z0-9_-]+)\b",
                text,
            )
            if m and m.group(1).lower() not in {"target", "targets", "set", "usa", "use", "load"}:
                name = m.group(1)
        if name:
            plan.append(Action(f"Ativar target `{name}`.", "set_target", {"target": name}))
        else:
            plan.append(
                Action(
                    "Qual pasta de target?",
                    "_note",
                    {"message": "ex: usa o target demo   |   set target targets/demo"},
                )
            )

    if "make_dir" in intents:
        paths = extract_path_mentions(text)
        folder = paths[0] if paths else _folder_from_text(text)
        if folder:
            plan.append(
                Action(
                    f"Criar pasta `{folder}` (approve).",
                    "make_dir",
                    {"path": str(folder)},
                )
            )
        else:
            plan.append(
                Action(
                    "Preciso do caminho da pasta.",
                    "_note",
                    {"message": "ex: cria uma pasta em Downloads/lab-notes"},
                )
            )

    if "delete_path" in intents:
        paths = extract_path_mentions(text)
        if paths:
            plan.append(
                Action(
                    f"Apagar `{paths[0]}` (approve).",
                    "delete_path",
                    {"path": paths[0]},
                )
            )
        else:
            plan.append(
                Action(
                    "Qual caminho apagar?",
                    "_note",
                    {"message": "ex: apaga o arquivo Downloads/old-scope.md"},
                )
            )

    if "map_surface" in intents and host:
        seed = target if target and "://" in str(target) else f"https://{host}/"
        plan.append(
            Action(
                f"Mapear surface de {host} (dry-run unless approve).",
                "map_surface",
                {
                    "target_dir": interp.target_dir,
                    "seed": seed,
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )

    if "http_request" in intents and (target or host):
        url = target if target and "://" in str(target) else (f"https://{host}/" if host else "")
        if url:
            plan.append(
                Action(
                    f"HTTP request → {url} (dry-run unless approve).",
                    "http_request",
                    {
                        "target_dir": interp.target_dir,
                        "url": url,
                        "method": "GET",
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )

    if "show_identity" in intents:
        plan.append(
            Action(
                "Show masked sessions/headers for this target.",
                "show_identity",
                {"target_dir": interp.target_dir},
            )
        )

    if "set_account" in intents:
        slots = _parse_set_account(text)
        if slots and (slots.get("username") or slots.get("password")):
            args = {
                "target_dir": interp.target_dir,
                "name": slots["name"],
            }
            if slots.get("username"):
                args["username"] = slots["username"]
            if slots.get("password"):
                args["password"] = slots["password"]
            plan.append(
                Action(
                    f"Gravar conta {slots['name']} em accounts.yaml (approve).",
                    "set_account",
                    args,
                )
            )
        else:
            plan.append(
                Action(
                    "Preciso de conta A/B + email/senha.",
                    "_note",
                    {
                        "message": (
                            "ex: conta A email user@x.com senha Secret123 em targets/demo\n"
                            "ou: set account B username=b@x.com password=pass"
                        )
                    },
                )
            )
        # Operator credential write is a single-job turn (don't also hunt)
        return plan

    if "extract_page" in intents and (target or host):
        url = target if target and "://" in str(target) else (f"https://{host}/" if host else "")
        if url:
            plan.append(
                Action(
                    f"Extrair conteúdo de {url} (dry-run unless approve).",
                    "extract_page",
                    {
                        "target_dir": interp.target_dir,
                        "url": url,
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )
        else:
            plan.append(
                Action(
                    "Qual URL extrair?",
                    "_note",
                    {"message": "ex: extrai o conteúdo de https://example.com/login"},
                )
            )
        return plan

    if "edit_file" in intents:
        paths = extract_path_mentions(text)
        path = paths[0] if paths else _parse_create_file_path(text)
        repl = _parse_edit_replace(text)
        if path and repl:
            plan.append(
                Action(
                    f"Editar `{path}` (approve).",
                    "edit_file",
                    {
                        "path": path,
                        "old_string": repl[0],
                        "new_string": repl[1],
                    },
                )
            )
        else:
            plan.append(
                Action(
                    "Preciso do caminho + troca X por Y.",
                    "_note",
                    {
                        "message": (
                            'ex: edita o arquivo Downloads/notes.md troca "foo" por "bar"'
                        )
                    },
                )
            )
        return plan

    if "set_session" in intents:
        # 1) Inline bearer/cookie
        m = re.search(
            r"session\s+([A-Za-z0-9_-]+)\s+(?:bearer|authorization)\s+(\S+)",
            text,
            re.I,
        )
        m_cookie = re.search(r"session\s+([A-Za-z0-9_-]+)\s+cookie\s+(\S+)", text, re.I)
        # 2) NL: "credenciais no arquivo X" / "tokens in file Y"
        paths = extract_path_mentions(text)
        cred_paths = [
            p
            for p in paths
            if not p.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))
        ]
        if m:
            plan.append(
                Action(
                    f"Save session {m.group(1)} bearer (gitignored).",
                    "set_session",
                    {
                        "target_dir": interp.target_dir,
                        "name": m.group(1),
                        "authorization": m.group(2),
                    },
                )
            )
        elif m_cookie:
            plan.append(
                Action(
                    f"Save session {m_cookie.group(1)} cookie (gitignored).",
                    "set_session",
                    {
                        "target_dir": interp.target_dir,
                        "name": m_cookie.group(1),
                        "cookie": m_cookie.group(2),
                    },
                )
            )
        elif cred_paths:
            plan.append(
                Action(
                    f"Ler credenciais em `{cred_paths[0]}` e gravar sessões A/B (sem /session).",
                    "load_sessions_from_file",
                    {
                        "target_dir": interp.target_dir,
                        "path": cred_paths[0],
                        "write": True,
                    },
                )
            )
        else:
            # Look for common relative secrets path mentioned loosely
            m_path = re.search(
                r"(?i)(?:arquivo|file|path|em|in)\s+[\"']?([^\s\"']+)[\"']?",
                text,
            )
            if m_path and any(
                x in m_path.group(1).lower()
                for x in (".yaml", ".yml", ".json", ".env", ".txt", "session", "token", "secret")
            ):
                plan.append(
                    Action(
                        f"Ler credenciais em `{m_path.group(1)}` e gravar sessões.",
                        "load_sessions_from_file",
                        {
                            "target_dir": interp.target_dir,
                            "path": m_path.group(1),
                            "write": True,
                        },
                    )
                )
            else:
                plan.append(
                    Action(
                        "Preciso do caminho do arquivo de credenciais (ou bearer/cookie inline).",
                        "_note",
                        {
                            "message": (
                                "ex: as credenciais estão no arquivo tokens.yaml na pasta Downloads\n"
                                "ou: set session A bearer <token>\n"
                                "(/session é só atalho — não é obrigatório)"
                            )
                        },
                    )
                )

    if "read_image" in intents:
        img_paths = [
            p
            for p in extract_path_mentions(text)
            if p.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))
        ]
        if not img_paths:
            m_img = re.search(
                r"(?i)((?:[\w./\\:~-])+\.(?:png|jpe?g|webp|gif|bmp))",
                text,
            )
            if m_img:
                img_paths = [m_img.group(1)]
        if img_paths:
            plan.append(
                Action(
                    f"Ler imagem `{img_paths[0]}` (OCR/visão) — sem comando especial.",
                    "read_image",
                    {"path": img_paths[0], "question": text[:300]},
                )
            )
        else:
            plan.append(
                Action(
                    "Você pediu para ler uma imagem mas não deu o caminho.",
                    "_note",
                    {
                        "message": (
                            "ex: leia a imagem Downloads/scope.png\n"
                            "ou: leia Desktop/scope.png e salva os hosts no SCOPE"
                        )
                    },
                )
            )

    if "import_har" in intents:
        har_paths = [p for p in extract_path_mentions(text) if p.lower().endswith(".har")]
        if not har_paths:
            m = re.search(r"(?i)((?:[\w./\\:~-])+\.har)", text)
            if m:
                har_paths = [m.group(1)]
        if har_paths:
            plan.append(
                Action(
                    f"Importar HAR `{har_paths[0]}` → surface.",
                    "import_har",
                    {"target_dir": interp.target_dir, "path": har_paths[0]},
                )
            )

    if "analyze_js" in intents:
        js_paths = [
            p
            for p in extract_path_mentions(text)
            if p.lower().endswith(".js") or "http" in p.lower()
        ]
        m = re.search(r"(https?://\S+\.js\S*)", text, re.I)
        source = m.group(1).rstrip(".,;") if m else (js_paths[0] if js_paths else "")
        if not source:
            m2 = re.search(r"(?i)((?:[\w./\\:~-])+\.js)", text)
            source = m2.group(1) if m2 else ""
        if source:
            plan.append(
                Action(
                    f"Analisar JS `{source}` (endpoints/secrets).",
                    "analyze_js",
                    {
                        "target_dir": interp.target_dir,
                        "source": source,
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )

    if "analyze_jwt" in intents:
        m = re.search(r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", text)
        if m:
            plan.append(Action("Decode/analyze JWT.", "analyze_jwt", {"token": m.group(1)}))
        else:
            plan.append(
                Action(
                    "Cole o JWT no prompt (eyJ…).",
                    "_note",
                    {"message": "ex: analisa este jwt eyJhbGciOi..."},
                )
            )

    if "list_dir" in intents:
        # Prefer explicit folder after "pasta"
        m = re.search(
            r"(?i)(?:pasta|folder|dir(?:ectory)?)\s+[\"']?([^\s\"']+)[\"']?",
            text,
        )
        folder = m.group(1) if m else ""
        if not folder:
            for token in ("Downloads", "Desktop", "Documentos", "Documents"):
                if token.lower() in text.lower():
                    folder = token
                    break
        if folder:
            plan.append(Action(f"Listar pasta `{folder}`.", "list_dir", {"path": folder}))

    if "crt" in intents and host:
        plan.append(Action(f"Subdomains passivos (crt.sh) para {host}.", "crt_subdomains", {"domain": host}))
    if "wayback" in intents and host:
        plan.append(Action(f"URLs históricas (wayback) para {host}.", "wayback_urls", {"domain": host}))

    if "graphql" in intents and host:
        gurl = target if target and "graphql" in (target or "").lower() else (
            (host if "://" in host else f"https://{host}") + "/graphql"
        )
        plan.append(
            Action(
                f"GraphQL introspection em {gurl}.",
                "graphql_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": gurl,
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "cors" in intents and (target or host):
        plan.append(
            Action(
                "CORS Origin reflection probe.",
                "cors_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "open_redirect" in intents and (target or host):
        plan.append(
            Action(
                "Open redirect probe.",
                "open_redirect_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "mine_params" in intents and (target or host):
        plan.append(
            Action(
                "Hidden parameter mining.",
                "mine_params",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "analyze_headers" in intents and (target or host):
        plan.append(
            Action(
                "Security headers / tech fingerprint.",
                "analyze_headers",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )

    for inj, tool, param in (
        ("lfi", "lfi_probe", "file"),
        ("ssti", "ssti_probe", "q"),
        ("xxe", "xxe_probe", None),
        ("ssrf", "ssrf_probe", "url"),
    ):
        if inj in intents and (target or host):
            args: dict[str, Any] = {
                "target_dir": interp.target_dir,
                "url": target or (host if "://" in (host or "") else f"https://{host}"),
                "approve": interp.approve,
                "force": interp.force,
            }
            if param:
                args["param"] = param
            plan.append(Action(f"{inj.upper()} probe.", tool, args))

    if "idor_probe" in intents and (target or host):
        plan.append(
            Action(
                "Check A/B sessions are loaded (masked).",
                "show_identity",
                {"target_dir": interp.target_dir},
            )
        )
        plan.append(
            Action(
                "Systematic IDOR A/B ownership probe.",
                "idor_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "discover_paths" in intents and (target or host):
        plan.append(
            Action(
                "Capped content discovery / path fuzz.",
                "discover_paths",
                {
                    "target_dir": interp.target_dir,
                    "base_url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "oob" in intents:
        plan.append(Action("Mint OOB/blind canary.", "oob_mint", {"kind": "ssrf"}))
        if "oob_poll" not in intents:
            plan.append(Action("Interactsh/OOB status.", "interactsh_status", {}))
    if "oob_poll" in intents:
        plan.append(Action("Poll stored OOB canary.", "interactsh_poll", {"wait": True}))
    if "hunt_checklist" in intents:
        plan.append(
            Action("Pre-hunt checklist.", "hunt_checklist", {"target_dir": interp.target_dir})
        )
    if "hunt_pause" in intents:
        plan.append(Action("Pause hunt loop.", "hunt_pause", {"target_dir": interp.target_dir}))
    if "hunt_resume" in intents:
        plan.append(
            Action("Clear hunt pause flag.", "hunt_resume_flag", {"target_dir": interp.target_dir})
        )
        if target or host:
            plan.append(
                Action(
                    "Resume autonomous hunt from saved state.",
                    "run_hunt",
                    {
                        "target_dir": interp.target_dir,
                        "prompt": text[:400],
                        "host": host or "",
                        "approve": interp.approve,
                        "force": interp.force,
                        "resume": True,
                    },
                )
            )
        return plan

    if "idp_capture" in intents and (target or host):
        sess = "A"
        m_sess = re.search(r"(?i)\b(?:sess[aã]o|session)\s*([AB])\b", text)
        if m_sess:
            sess = m_sess.group(1).upper()
        plan.append(
            Action(
                f"Headed IdP capture → session {sess}.",
                "browser_capture_session",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "session": sess,
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
        return plan
    if "hunt_telemetry" in intents:
        plan.append(
            Action("Hunt telemetry stats.", "hunt_telemetry", {"target_dir": interp.target_dir})
        )
    if "cdp" in intents:
        plan.append(Action("Probe local CDP endpoint.", "cdp_attach", {"approve": interp.approve}))
    if "mass_assignment" in intents and (target or host):
        plan.append(
            Action(
                "Mass-assignment probe.",
                "mass_assignment_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "method_override" in intents and (target or host):
        plan.append(
            Action(
                "Method override probe.",
                "method_override_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "hpp" in intents and (target or host):
        plan.append(
            Action(
                "HTTP parameter pollution.",
                "hpp_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "submit_ready" in intents:
        plan.append(
            Action(
                "Mark finding ready for human submit.",
                "submit_ready",
                {"target_dir": interp.target_dir},
            )
        )
    if "detect_login" in intents and (target or host):
        plan.append(
            Action(
                "Detect login surface (form/JSON/SSO).",
                "detect_login",
                {
                    "target_dir": interp.target_dir,
                    "base_url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                    "persist": bool(interp.approve),
                },
            )
        )
        return plan

    if "session_smoke" in intents and (target or host):
        sess = "A"
        m_sess = re.search(r"(?i)\b(?:sess[aã]o|session)\s*([AB])\b", text)
        if m_sess:
            sess = m_sess.group(1).upper()
        plan.append(
            Action(
                f"Whoami smoke for session {sess}.",
                "session_smoke",
                {
                    "target_dir": interp.target_dir,
                    "base_url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "session": sess,
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
        return plan

    if "session_bootstrap" in intents and (target or host):
        plan.append(
            Action(
                "Show masked accounts readiness.",
                "show_accounts",
                {"target_dir": interp.target_dir},
            )
        )
        plan.append(
            Action(
                "Bootstrap A/B sessions from accounts.yaml.",
                "session_bootstrap",
                {
                    "target_dir": interp.target_dir,
                    "base_url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )

    if "race" in intents and (target or host):
        plan.append(
            Action(
                "Bounded race / parallel burst.",
                "race_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": target or (host if "://" in (host or "") else f"https://{host}"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "websocket" in intents and (target or host):
        url = target or host or ""
        if url.startswith("http://"):
            url = "ws://" + url[len("http://") :]
        elif url.startswith("https://"):
            url = "wss://" + url[len("https://") :]
        elif "://" not in url:
            url = f"wss://{url}"
        plan.append(
            Action(
                "Websocket handshake probe.",
                "websocket_probe",
                {
                    "target_dir": interp.target_dir,
                    "url": url,
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )
    if "mobsf" in intents:
        plan.append(Action("MobSF health check.", "mobsf_health", {}))
    if "frida" in intents:
        plan.append(Action("Frida/Objection status.", "frida_status", {}))

    if "oauth" in intents and (target or host):
        plan.append(
            Action(
                "OAuth authorize probe.",
                "oauth_probe",
                {
                    "target_dir": interp.target_dir,
                    "authorize_url": target
                    or (host if "://" in (host or "") else f"https://{host}/oauth/authorize"),
                    "approve": interp.approve,
                    "force": interp.force,
                },
            )
        )

    if "jwt_active" in intents:
        m = re.search(r"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", text)
        if m and (target or host):
            plan.append(
                Action(
                    "JWT active bypass variants.",
                    "jwt_active_probe",
                    {
                        "target_dir": interp.target_dir,
                        "url": target or (host if "://" in (host or "") else f"https://{host}"),
                        "token": m.group(1),
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )
        elif m:
            plan.append(Action("Decode JWT first.", "analyze_jwt", {"token": m.group(1)}))

    if "build_chains" in intents:
        plan.append(
            Action(
                "Build A→B exploit chains from FINDINGS.",
                "build_chains",
                {"target_dir": interp.target_dir},
            )
        )
    if "mobile_bridge" in intents or (
        "mobile" in intents
        and (
            any(p.lower().endswith(".har") for p in extract_path_mentions(text))
            or ".har" in text.lower()
        )
        and (
            any(p.lower().endswith(".apk") for p in extract_path_mentions(text))
            or ".apk" in text.lower()
            or _wants(text, "hunt", "explora", "bridge")
        )
    ):
        apk_paths = [p for p in extract_path_mentions(text) if p.lower().endswith(".apk")]
        har_paths = [p for p in extract_path_mentions(text) if p.lower().endswith(".har")]
        m_apk = re.search(r"(?i)((?:[\w./\\:~-])+\.apk)", text)
        m_har = re.search(r"(?i)((?:[\w./\\:~-])+\.har)", text)
        if m_apk and not apk_paths:
            apk_paths = [m_apk.group(1)]
        if m_har and not har_paths:
            har_paths = [m_har.group(1)]
        args: dict[str, Any] = {
            "target_dir": interp.target_dir,
            "approve": interp.approve,
            "force": interp.force,
            "start_hunt": bool(interp.approve and _wants(text, "hunt", "explora", "cac", "caça")),
        }
        if apk_paths:
            args["apk_path"] = apk_paths[0]
        if har_paths:
            args["har_path"] = har_paths[0]
        if host:
            args["host"] = host
        plan.append(
            Action(
                "Mobile bridge: APK/HAR → surface (+ optional hunt).",
                "mobile_bridge",
                args,
            )
        )
    elif "mobile" in intents:
        apk_paths = [p for p in extract_path_mentions(text) if p.lower().endswith(".apk")]
        m = re.search(r"(?i)((?:[\w./\\:~-])+\.apk)", text)
        if m and not apk_paths:
            apk_paths = [m.group(1)]
        if apk_paths:
            plan.append(
                Action(
                    f"Inspect APK `{apk_paths[0]}`.",
                    "inspect_apk",
                    {"target_dir": interp.target_dir, "path": apk_paths[0]},
                )
            )
        elif _wants(text, "adb", "devices", "emulador", "emulator"):
            plan.append(Action("List adb devices.", "adb_devices", {}))
        else:
            plan.append(
                Action(
                    "Mobile toolchain status + checklist.",
                    "mobile_status",
                    {"task": text[:200]},
                )
            )
    if "browser_session" in intents and "browser_diff" not in intents:
        url = target or (host if host and "://" in host else (f"https://{host}" if host else ""))
        sess = "A"
        m = re.search(r"(?i)(?:session|sess[aã]o)\s*([AB])\b", text)
        if m:
            sess = m.group(1).upper()
        elif _wants(text, "session b", "sessao b", "sessão b"):
            sess = "B"
        if url:
            plan.append(
                Action(
                    f"Browser with session {sess} at {url}.",
                    "browser_with_session",
                    {
                        "target_dir": interp.target_dir,
                        "url": url,
                        "session": sess,
                        "approve": interp.approve,
                        "force": interp.force,
                        "capture_network": _wants(text, "network", "rede", "xhr"),
                    },
                )
            )
        else:
            plan.append(
                Action(
                    "Need URL for browser_with_session.",
                    "_note",
                    {"message": "ex: abre autenticado com sessão A em https://app.example.com targets/demo"},
                )
            )
    if "browser_diff" in intents:
        url = target or (host if host and "://" in host else (f"https://{host}" if host else ""))
        if url:
            plan.append(
                Action(
                    f"Browser A vs B diff at {url}.",
                    "browser_diff_sessions",
                    {
                        "target_dir": interp.target_dir,
                        "url": url,
                        "session_a": "A",
                        "session_b": "B",
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )
        else:
            plan.append(
                Action(
                    "Need URL for browser_diff_sessions.",
                    "_note",
                    {"message": "ex: compara sessão A vs B em https://app.example.com/api/me targets/demo"},
                )
            )
    if "browser_cookies" in intents or "browser_storage" in intents or "browser_network" in intents:
        url = target or (host if host and "://" in host else (f"https://{host}" if host else ""))
        common = {
            "target_dir": interp.target_dir,
            "url": url or "https://example.com",
            "approve": interp.approve,
            "force": interp.force,
        }
        if not url:
            plan.append(Action("Browser status / install hint.", "browser_hint", {"task": text[:200]}))
        else:
            if "browser_cookies" in intents:
                plan.append(Action(f"List cookies at {url}.", "browser_cookies", dict(common)))
            if "browser_storage" in intents:
                plan.append(Action(f"Dump web storage at {url}.", "browser_storage", dict(common)))
            if "browser_network" in intents:
                plan.append(
                    Action(
                        f"Capture browser network at {url}.",
                        "browser_network",
                        {**common, "seed_surface": True},
                    )
                )
    if "browser" in intents and not any(
        x in intents
        for x in (
            "browser_cookies",
            "browser_storage",
            "browser_network",
            "browser_session",
            "browser_diff",
        )
    ):
        url = target or (host if host and "://" in host else (f"https://{host}" if host else ""))
        if url and _wants(text, "screenshot", "print", "tire um print"):
            plan.append(
                Action(
                    f"Browser screenshot of {url}.",
                    "browser_screenshot",
                    {
                        "target_dir": interp.target_dir,
                        "url": url,
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )
        elif url:
            plan.append(
                Action(
                    f"Browser navigate {url}.",
                    "browser_navigate",
                    {
                        "target_dir": interp.target_dir,
                        "url": url,
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )
        else:
            plan.append(Action("Browser status / install hint.", "browser_hint", {"task": text[:200]}))
    if "import_burp" in intents:
        paths = [p for p in extract_path_mentions(text) if p.lower().endswith(".xml")]
        m = re.search(r"(?i)((?:[\w./\\:~-])+\.xml)", text)
        if m and not paths:
            paths = [m.group(1)]
        if paths:
            plan.append(
                Action(
                    f"Import Burp XML `{paths[0]}` → surface.",
                    "import_burp_xml",
                    {"target_dir": interp.target_dir, "path": paths[0]},
                )
            )
    if "burp_rest" in intents:
        plan.append(Action("Check local Burp REST listener.", "burp_rest_health", {}))
    if "burp_ensure" in intents:
        plan.append(
            Action(
                "Start/configure Burp Community + wait for local REST.",
                "burp_ensure",
                {"base_url": "http://127.0.0.1:1337", "wait_sec": 45},
            )
        )
    if "stack_prepare" in intents:
        plan.append(
            Action(
                "Fix Go/gau/subfinder PATH and smoke-check recon CLIs.",
                "stack_prepare",
                {"persist_shell_rc": False},
            )
        )
    if "lab_exec" in intents:
        plan.append(
            Action(
                "Lab shell needs an explicit command in the prompt.",
                "_note",
                {
                    "message": (
                        "ex: lab_exec: which gau\n"
                        "ou: com sudo apt install -y golang-go\n"
                        "(senha: HACKBOT_SUDO_PASS ou .hackbot/sudo_pass)"
                    )
                },
            )
        )
    if _wants(text, "burp replay", "replay burp", "burp send", "repeater", "replay history"):
        replay_url = ""
        if target and "://" in target:
            replay_url = target
        elif host:
            replay_url = f"https://{host}/"
        if replay_url:
            plan.append(
                Action(
                    "Burp control-plane replay (dry-run).",
                    "burp_replay",
                    {
                        "target_dir": interp.target_dir,
                        "url": replay_url,
                        "approve": False,
                        "force": True,
                    },
                )
            )
        else:
            plan.append(Action("Check Burp REST before replay.", "burp_rest_health", {}))
    if "learn_suggest" in intents:
        plan.append(
            Action(
                "Suggest modules from past hunts.",
                "learn_suggest",
                {"host": host or ""},
            )
        )
    if "browser_hint" in intents and "browser" not in intents and not any(
        x in intents for x in ("browser_cookies", "browser_storage", "browser_network")
    ):
        plan.append(Action("Browser CDP checklist.", "browser_hint", {"task": text[:200]}))

    if "knowledge" in intents:
        plan.append(
            Action(
                f"Pull the mandatory study notes for this task (class={','.join(interp.classes)}).",
                "open_knowledge",
                {"task": text, "max_chars": 3000},
            )
        )
        plan.append(
            Action(
                f"Open the falsifiable playbook for {cls}.",
                "open_playbook",
                {"task": cls, "endpoint": target or ""},
            )
        )

    # Scope check whenever we have a host, or the user explicitly asked.
    if host and ("scope" in intents or "plan" in intents or "run" in intents or "playbook_run" in intents):
        action_label = interp.tool or cls
        plan.append(
            Action(
                f"Confirm {host} is in scope for {interp.target_dir} before anything active.",
                "scope_check",
                {"target_dir": interp.target_dir, "host": host, "action": action_label},
            )
        )
    elif "scope" in intents and not host:
        plan.append(
            Action(
                "No host given, so read the SCOPE.md so we can see what's allowed.",
                "read_file",
                {"path": f"{interp.target_dir}/SCOPE.md", "max_chars": 4000},
            )
        )

    if interp.force and ("run" in intents or "playbook_run" in intents):
        plan.append(
            Action(
                "FORCE is on — ALL SCOPE gates may be overridden (incl. OUT_OF_SCOPE); "
                "approve still required for live traffic. Responsibility is yours.",
                "_note",
                {"message": "force override active (operator responsibility)"},
            )
        )

    if "plan" in intents and "playbook_run" not in intents:
        pb = playbook_for(cls)
        step = pb.steps[0] if pb.steps else None
        hyp = step.hypothesis if step else pb.summary
        cmd = (step.command if step else "").replace("{host}", target or "<host>")
        plan.append(
            Action(
                f"Draft a falsifiable hunt step for {cls}.",
                "make_plan",
                {
                    "target_dir": interp.target_dir,
                    "hypothesis": hyp,
                    "target": target or "<in-scope host>",
                    "action": cls,
                    "command": cmd or f"# see playbook {cls}",
                },
            )
        )

    if "campaign" in intents:
        if not host:
            plan.append(
                Action(
                    "Campaign/hunt precisa de host in-scope.",
                    "_note",
                    {
                        "message": (
                            "ex: /hunt explora o que der em example.com --approve\n"
                            "ou: de acordo com o scope, faça DDoS e secrets em example.com"
                        )
                    },
                )
            )
        else:
            mode = "EXECUTE" if interp.approve else "dry-run"
            from .campaign import resolve_modules

            mods, used_default = resolve_modules(text)
            # Open-ended / default-pack / recon-only → autonomous OODA hunt.
            # Named offensive classes (dos, secrets, idor, …) keep run_campaign.
            named = [m for m in mods if m.id not in {"recon"}]
            use_hunt = used_default or not named or bool(
                re.search(
                    r"\b(/hunt|autonom|explora o que|explore what|go hunt|cacada|caçada|"
                    r"quebra o que|tudo que der|faz o que puder)\b",
                    text,
                    re.I,
                )
            )
            if use_hunt:
                note = " (autonomous OODA hunt)"
                plan.append(
                    Action(
                        f"{mode}: hunt autônomo contra {host}{note} → surface + specialists + FINDINGS.",
                        "run_hunt",
                        {
                            "target_dir": interp.target_dir,
                            "prompt": text,
                            "host": host,
                            "approve": interp.approve,
                            "force": interp.force,
                        },
                    )
                )
                if used_default:
                    plan.insert(
                        -1,
                        Action(
                            "Prompt aberto — usando /hunt (surface → chain → validate).",
                            "_note",
                            {
                                "message": (
                                    "Autonomous hunt maps surface then chains secrets/auth/IDOR/injection. "
                                    "Name specific classes to use the older campaign pack instead."
                                )
                            },
                        ),
                    )
            else:
                note = ""
                if used_default:
                    note = " (default pack — prompt was vague)"
                plan.append(
                    Action(
                        f"{mode}: campanha contra {host}{note} → relatório FOUND/NOT_FOUND.",
                        "run_campaign",
                        {
                            "target_dir": interp.target_dir,
                            "host": host,
                            "prompt": text,
                            "endpoint": target or host,
                            "approve": interp.approve,
                            "force": interp.force,
                        },
                    )
                )
                if used_default:
                    plan.insert(
                        -1,
                        Action(
                            "Prompt sem classes claras — usando pacote padrão de hunt.",
                            "_note",
                            {
                                "message": (
                                    "default pack: recon, secrets, auth-bypass, brute, dos. "
                                    "Name classes to narrow; /force for level-3."
                                )
                            },
                        ),
                    )

    if "playbook_run" in intents and "campaign" not in intents:
        if not host:
            plan.append(
                Action(
                    f"You asked to run the {cls} playbook but gave no host.",
                    "_note",
                    {
                        "message": (
                            f"give me a host, e.g. 'test {cls} on example.com for {interp.target_dir}' "
                            "or set /target first"
                        )
                    },
                )
            )
        else:
            needs_ab = cls in {"idor", "bola", "bac", "bfla", "authz", "ssrf"}
            if needs_ab:
                plan.append(
                    Action(
                        "Check A/B sessions are loaded (masked).",
                        "show_identity",
                        {"target_dir": interp.target_dir},
                    )
                )
                tdir = Path(interp.target_dir)
                if not tdir.is_absolute():
                    tdir = ROOT / tdir
                ident = load_identity(tdir)
                ready = set(ident.ready_sessions())
                if not ({"A", "B"} <= ready or len(ready) >= 2):
                    plan.append(
                        Action(
                            "A/B sessions missing — authz playbook will fail without them.",
                            "_note",
                            {
                                "message": (
                                    "load secrets first: copy sessions.example.yaml -> sessions.yaml "
                                    "or `set session A bearer <token>` and same for B"
                                )
                            },
                        )
                    )
            mode = "EXECUTE" if interp.approve else "dry-run"
            plan.append(
                Action(
                    f"{mode}: executable playbook `{cls}` against {host}.",
                    "run_playbook",
                    {
                        "target_dir": interp.target_dir,
                        "task": cls,
                        "host": host,
                        "endpoint": target or host,
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            )

    if "run" in intents and "playbook_run" not in intents:
        tool = interp.tool or "httpx"
        if not host:
            plan.append(
                Action(
                    f"You asked to run {tool} but gave no in-scope host, so I'll stop and ask for one.",
                    "_note",
                    {
                        "message": (
                            f"give me a host, e.g. 'dry-run {tool} on example.com for {interp.target_dir}'"
                        )
                    },
                )
            )
        else:
            run_args: dict[str, Any] = {
                "target_dir": interp.target_dir,
                "tool": tool,
                "host": host,
                "approve": interp.approve,
                "force": interp.force,
            }
            if tool == "ffuf":
                run_args["wordlist"] = "<wordlist>"
            mode = "EXECUTE (active traffic)" if interp.approve else "dry-run (print only)"
            plan.append(Action(f"{mode}: {tool} against {host}.", "run_tool", run_args))

    if "report" in intents:
        platform = interp.platform or "generic"
        plan.append(
            Action(
                f"Write a {platform} bug-bounty report draft from FINDINGS.md.",
                "write_report_draft",
                {
                    "target_dir": interp.target_dir,
                    "platform": platform,
                    "finding_id": "latest",
                },
            )
        )

    if "read" in intents and not any(
        a.tool in {"read_file", "load_sessions_from_file", "read_image"} for a in plan
    ):
        paths = extract_path_mentions(text)
        text_paths = [
            p
            for p in paths
            if not p.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))
        ]
        if text_paths:
            path = text_paths[0]
        else:
            m = re.search(
                r"([a-z0-9_./\\:~-]+\.(?:md|txt|json|xml|yaml|yml|env))",
                text,
                re.IGNORECASE,
            )
            path = m.group(1) if m else f"{interp.target_dir}/SCOPE.md"
        plan.append(Action(f"Read {path}.", "read_file", {"path": path, "max_chars": 4000}))

    if not plan:
        plan.append(
            Action(
                "Não mapeei um passo concreto — fala natural funciona.",
                "_note",
                {
                    "message": (
                        "Exemplos:\n"
                        "- as credenciais estão no arquivo tokens.yaml em Downloads; "
                        "explora example.com approve\n"
                        "- leia a imagem Desktop/scope.png\n"
                        "- explora vulnerabilidades em example.com (targets/demo)\n"
                        "(/hunt e /session são atalhos opcionais)"
                    )
                },
            )
        )

    return plan


# ---------------------------------------------------------------------------
# execution + rendering
# ---------------------------------------------------------------------------

def _render_result(tool: str, result_json: str) -> None:
    try:
        data = json.loads(result_json)
    except json.JSONDecodeError:
        ui.code_panel(result_json, title="result", lexer="text")
        return

    if isinstance(data, dict) and data.get("ok") is False:
        ui.error(data.get("error", "tool error"))
        return

    if tool == "scope_check":
        ui.scope_result(data.get("host", "?"), data.get("status", "?"))
        if "aggression" in data:
            ui.aggression_result(int(data["aggression"]), data.get("policy_quote", ""))
        return

    if tool == "open_knowledge":
        preview = data.get("notes", "")
        ui.kv("class", data.get("class", "?"))
        ui.markdown_panel(preview[:2500] or "(no notes)", title="knowledge")
        return

    if tool == "open_playbook":
        ui.markdown_panel(data.get("playbook", "")[:4000], title=f"playbook:{data.get('class', '?')}")
        return

    if tool == "run_playbook":
        if data.get("executed"):
            ui.success(f"playbook {data.get('class')} executed ({len(data.get('results') or [])} steps)")
            if data.get("verdict"):
                ui.kv("verdict", str(data["verdict"]))
        else:
            ui.info(f"playbook {data.get('class')} dry-run — {len(data.get('steps') or [])} steps")
            if data.get("playbook"):
                ui.markdown_panel(str(data["playbook"])[:3000], title="playbook")
        ui.code_panel(json.dumps(data, indent=2)[:4000], title="run_playbook", lexer="json")
        return

    if tool == "http_request":
        # Runner already printed a compact action line; avoid kv spam.
        if ui.verbose_enabled():
            ui.kv("label", str(data.get("label", "?")))
            ui.kv("status", str(data.get("status", "?")))
        return

    if tool == "assert_diff":
        ui.kv("verdict", str(data.get("verdict", "?")))
        ui.info(str(data.get("reason", "")))
        return

    if tool == "log_finding":
        ui.success(f"logged {data.get('finding_id')}")
        ui.path_line("path", data.get("path", ""))
        return

    if tool == "show_identity":
        ui.kv("ready", ", ".join(data.get("ready") or []) or "(none)")
        ui.code_panel(json.dumps(data.get("sessions") or {}, indent=2), title="sessions (masked)", lexer="json")
        return

    if tool == "run_campaign":
        ui.kv("found", str(data.get("found_count", 0)))
        if data.get("finding_ids"):
            ui.kv("findings", ", ".join(data["finding_ids"]))
        if data.get("report_md"):
            ui.markdown_panel(str(data["report_md"]), title="campaign results")
        return

    if tool == "run_hunt":
        ui.kv("acts", str(data.get("acts_done", 0)))
        ui.kv("findings", ", ".join(data.get("findings") or []) or "(none)")
        ui.kv("stop", str(data.get("stop_reason") or "complete"))
        return

    if tool == "map_surface":
        ui.kv("endpoints", str(data.get("endpoints", 0)))
        return

    if tool == "load_sessions_from_file":
        ui.kv("saved", ", ".join(data.get("saved") or []) or "(preview)")
        ui.kv("path", str(data.get("path") or ""))
        return

    if tool == "set_account":
        ui.kv("saved", str(data.get("saved") or "?"))
        ui.kv("ready", ", ".join(data.get("ready") or []) or "(none)")
        return

    if tool == "extract_page":
        ui.kv("title", str(data.get("title") or "?"))
        ui.kv("status", str(data.get("status") or data.get("dry_run") or "?"))
        if data.get("thin_content"):
            ui.warn(str(data.get("hint") or "thin content"))
        text = str(data.get("text") or "")
        if text:
            ui.markdown_panel(text[:2500], title="page text")
        return

    if tool == "read_image":
        ui.kv("source", str(data.get("source") or "?"))
        return

    if tool == "make_plan":
        ui.markdown_panel(data.get("plan", ""), title="hunt step")
        if not data.get("in_scope", False):
            ui.warn("host NOT confirmed in SCOPE.md - this plan is inference, no active traffic yet")
        return

    if tool == "run_tool":
        return

    if tool in ("write_report_draft", "save_evidence"):
        if data.get("path"):
            ui.success("wrote file")
            ui.path_line("path", data["path"])
        return

    if tool == "read_file":
        if data.get("ok"):
            ui.file_panel(data.get("path", "file"), (data.get("text") or "")[:4000])
        else:
            ui.warn(f"missing: {data.get('path')}")
        return

    if tool == "list_targets":
        names = data.get("targets", [])
        ui.kv("targets", ", ".join(names) or "(none - run: hackbot cmd target-init demo)")
        return

    ui.code_panel(json.dumps(data, indent=2), title="result", lexer="json")


def run_local_agent(
    user_prompt: str,
    *,
    approve_fn: ApproveFn | None = None,
) -> None:
    """Read the prompt, show the plan, execute each step. No LLM required.

    When offline confidence is low and a model provider is configured,
    prompt_router asks the model for a PT-BR/EN JSON interpretation, then
    we still execute via the same tools (SCOPE / approve / force).
    """

    if is_chat_prompt(user_prompt):
        ui.markdown_panel(
            "Hey. Offline brain here (no model). **Fala natural** — não precisa de `/hunt` "
            "nem `/session`.\n\n"
            "Exemplos:\n"
            "- as credenciais estão no arquivo `tokens.yaml` em Downloads; explora "
            "example.com approve\n"
            "- leia a imagem `Desktop/scope.png`\n"
            "- explora o que der em example.com (targets/demo)\n\n"
            "PT-BR / EN ok. Modelo: `/provider`. "
            "`approve` / `/force` quando for tráfego real / level-3.",
            title="hackbot (offline)",
        )
        return

    from .prompt_router import needs_soft_clarify

    interp = interpret(user_prompt)
    route = route_prompt(
        user_prompt,
        host=interp.host,
        target_dir=interp.target_dir,
        intents=interp.intents,
        classes=interp.classes,
        approve=interp.approve,
        force=interp.force,
    )
    interp = _apply_route(interp, route)
    plan = build_plan(user_prompt, interp)
    # If router says campaign with modules, ensure a campaign action exists
    if route.intent == "campaign" and route.modules and not any(
        a.tool in {"run_campaign", "run_hunt"} for a in plan
    ):
        host = interp.host
        if host:
            plan = [
                Action(
                    f"Routed campaign ({route.source}): {', '.join(route.modules)}",
                    "run_campaign",
                    {
                        "target_dir": interp.target_dir,
                        "host": host,
                        "prompt": _campaign_prompt_from_route(user_prompt, route),
                        "endpoint": route.endpoint or interp.full_target or host,
                        "approve": interp.approve,
                        "force": interp.force,
                    },
                )
            ]

    # Ambiguous offline → clarify instead of inventing a default-pack hunt
    if needs_soft_clarify(
        confidence=route.confidence,
        intents=interp.intents,
        used_default_pack=route.used_default_pack,
        source=route.source,
    ):
        lang = (route.language or "en").lower()
        if lang.startswith("pt"):
            msg = (
                "Prompt ambíguo (confiança baixa). Diz o que quer, por exemplo:\n"
                "- crie um arquivo na pasta Downloads chamado scope.md\n"
                "- as credenciais estão no arquivo tokens.yaml; explora example.com\n"
                "- mapeia a surface de example.com (targets/demo)\n"
                "- testa idor em example.com approve\n"
                "- leia a imagem Desktop/scope.png\n"
                "Ou `/provider openai|anthropic|…` pra eu interpretar melhor."
            )
        else:
            msg = (
                "Ambiguous prompt (low confidence). Be concrete, e.g.:\n"
                "- create a file in Downloads called scope.md\n"
                "- credentials are in tokens.yaml; hunt example.com\n"
                "- map the surface of example.com (targets/demo)\n"
                "- test idor on example.com approve\n"
                "- read the image Desktop/scope.png\n"
                "Or `/provider openai|anthropic|…` so I can interpret better."
            )
        # Drop generic campaign/hunt when clarifying
        plan = [
            a
            for a in plan
            if a.tool not in {"run_campaign", "run_hunt", "run_playbook", "make_plan"}
        ]
        plan.insert(0, Action("Preciso de um pouco mais de detalhe.", "_note", {"message": msg}))

    understood = [
        f"- lang: `{route.language}`  route: `{route.source}`  confidence: `{route.confidence:.2f}`",
        f"- understood: {route.summary_for_ui()}",
        f"- target: `{interp.target_dir}`",
        f"- host: `{interp.host or '(none found)'}`",
        f"- bug class: `{','.join(interp.classes)}`",
    ]
    if route.modules:
        understood.append(f"- modules: `{', '.join(route.modules)}`")
    if interp.tool:
        understood.append(f"- tool: `{interp.tool}`")
    if interp.platform:
        understood.append(f"- platform: `{interp.platform}`")
    understood.append(f"- mode: `{'approve/active' if interp.approve else 'dry-run/safe'}`")
    understood.append(f"- force: `{'ON' if interp.force else 'off'}`")
    steps = "\n".join(f"{i}. {a.thought}" for i, a in enumerate(plan, 1))
    ui.markdown_panel(
        "**what I understood**\n" + "\n".join(understood) + "\n\n**plan**\n" + steps,
        title=f"thinking ({route.source})",
    )

    oneshot_force = bool(interp.force) and not is_forced()
    if oneshot_force:
        enable_force(quiet=True)
    try:
        _run_local_plan(plan, user_prompt=user_prompt, interp=interp, approve_fn=approve_fn)
    finally:
        if oneshot_force:
            disable_force(quiet=True)


def _run_local_plan(
    plan: list[Action],
    *,
    user_prompt: str,
    interp: Interpretation,
    approve_fn: ApproveFn | None,
) -> None:
    i = 0
    while i < len(plan):
        try:
            from .turn_bus import turn_cancel_requested

            if turn_cancel_requested():
                ui.warn("cancelled")
                return
        except Exception:  # noqa: BLE001
            pass
        action = plan[i]
        i += 1
        ui.rule(f"step {i}/{len(plan)}")
        ui.info(action.thought)
        if action.tool == "_note":
            ui.warn(action.args.get("message", ""))
            continue
        ui.kv("tool", action.tool)
        if action.args:
            ui.code_panel(json.dumps(action.args, indent=2), title="args", lexer="json")
        result = execute_tool(action.tool, action.args, approve_fn=approve_fn)
        _render_result(action.tool, result)

        if action.tool == "read_image":
            try:
                img_data = json.loads(result)
            except json.JSONDecodeError:
                img_data = {}
            ocr_blob = " ".join(
                str(img_data.get(k) or "")
                for k in ("ocr", "vision", "message")
            )
            wants_scope = _wants(
                user_prompt,
                "scope",
                "salva no scope",
                "salvar no scope",
                "atualiza o scope",
                "atualizar scope",
                "grava no scope",
                "write scope",
                "update scope",
            )
            hosts = _hosts_from_text(ocr_blob)
            if wants_scope and hosts and img_data.get("ok"):
                scope_path = str(Path(interp.target_dir) / "SCOPE.md")
                lines = "# Scope\n\n## In Scope\n\n" + "\n".join(f"- {h}" for h in hosts)
                lines += "\n\n## Explicitly Allowed\n\n- Automated scanning\n- Active testing\n"
                plan.append(
                    Action(
                        f"Gravar hosts do OCR em `{scope_path}` (approve).",
                        "write_file",
                        {"path": scope_path, "content": lines},
                    )
                )
                ui.info(f"OCR → {len(hosts)} host(s) — queuing write_file SCOPE.md")
            elif wants_scope and img_data.get("ok") and not hosts:
                plan.append(
                    Action(
                        "OCR sem hosts claros para SCOPE.",
                        "_note",
                        {
                            "message": (
                                "Li a imagem mas não achei domínios óbvios. "
                                "Diga os hosts ou cole o texto in-scope."
                            )
                        },
                    )
                )
            acct = _parse_set_account(user_prompt)
            if (
                acct
                and (acct.get("username") or acct.get("password"))
                and _wants(user_prompt, "imagem", "image", "screenshot", "png", "jpg")
            ):
                # Image turn that also embeds credentials in the utterance
                args = {"target_dir": interp.target_dir, "name": acct["name"]}
                if acct.get("username"):
                    args["username"] = acct["username"]
                if acct.get("password"):
                    args["password"] = acct["password"]
                if not any(a.tool == "set_account" for a in plan):
                    plan.append(
                        Action(
                            f"Gravar conta {acct['name']} citada junto da imagem (approve).",
                            "set_account",
                            args,
                        )
                    )

        if action.tool == "run_playbook":
            try:
                data = json.loads(result)
            except json.JSONDecodeError:
                data = {}
            verdict = (data.get("verdict") or "").lower()
            if data.get("executed") and verdict in {"confirmed", "likely"}:
                endpoint = action.args.get("endpoint") or action.args.get("host") or ""
                cls = data.get("class") or "finding"
                follow = [
                    Action(
                        f"Log {verdict} finding for {cls}.",
                        "log_finding",
                        {
                            "target_dir": action.args.get("target_dir"),
                            "title": f"{cls.upper()} on {endpoint}",
                            "class_name": cls,
                            "endpoint": endpoint,
                            "verdict": verdict,
                            "observed": f"Playbook verdict={verdict}",
                            "evidence": "See evidence/safe/ (http_* and diff_*)",
                            "next_step": "Draft and submit platform report",
                            "update_resume": True,
                        },
                    ),
                    Action(
                        "Draft report from latest finding.",
                        "write_report_draft",
                        {
                            "target_dir": action.args.get("target_dir"),
                            "platform": interp.platform or "generic",
                            "title": f"{cls.upper()} on {endpoint}",
                            "target": endpoint,
                            "finding_id": "latest",
                        },
                    ),
                ]
                plan.extend(follow)
                ui.info("verdict interesting — queuing log_finding + report draft")

    ui.success("offline plan finished")


def _apply_route(interp: Interpretation, route: RouteDecision) -> Interpretation:
    """Merge RouteDecision into Interpretation (host/target/approve/force/intents)."""
    if route.host and not interp.host:
        interp.host = route.host
        if not interp.full_target:
            interp.full_target = route.endpoint or route.host
    if route.endpoint:
        interp.full_target = route.endpoint
    if route.target_dir:
        interp.target_dir = route.target_dir
    if route.approve:
        interp.approve = True
    if route.force:
        interp.force = True
    if route.tool and not interp.tool:
        interp.tool = route.tool
    if route.modules:
        # Prefer routed modules as classes for playbook selection
        interp.classes = list(dict.fromkeys(route.modules + interp.classes))
    if route.intent == "campaign" and "campaign" not in interp.intents:
        interp.intents = ["campaign", *interp.intents]
    elif route.intent == "playbook" and "playbook_run" not in interp.intents:
        interp.intents = ["playbook_run", *interp.intents]
    elif route.intent == "run_tool" and "run" not in interp.intents:
        interp.intents = ["run", *interp.intents]
    elif route.intent == "scope" and "scope" not in interp.intents:
        interp.intents = ["scope", *interp.intents]
    elif route.intent == "knowledge" and "knowledge" not in interp.intents:
        interp.intents = ["knowledge", *interp.intents]
    return interp


def _campaign_prompt_from_route(original: str, route: RouteDecision) -> str:
    """Enrich campaign prompt with explicit module names for the executor."""
    if not route.modules:
        return original
    tags = " ".join(route.modules)
    return f"{original}\n\n[routed modules: {tags}]"
