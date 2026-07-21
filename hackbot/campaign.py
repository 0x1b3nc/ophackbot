"""Multi-attack campaign: NL prompt → modules → result report.

Resilient to paraphrase: normalize text, score synonyms, and fall back to a
default hunt pack when the operator clearly wants attacks but didn't name a
class. Authorized bounty only — level-3 still needs SCOPE or /force.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class AttackModule:
    id: str
    label: str
    kind: str  # playbook | tool
    task: str
    aggression: int
    keywords: tuple[str, ...]
    needs_sessions: bool = False
    needs_login_path: bool = False


MODULES: tuple[AttackModule, ...] = (
    AttackModule(
        id="recon",
        label="Recon / fingerprint",
        kind="playbook",
        task="recon",
        aggression=1,
        keywords=(
            "recon",
            "reconhecimento",
            "fingerprint",
            "mapear",
            "enumerate",
            "enumera",
            "descobrir host",
            "surface",
            "httpx",
            "o que tem",
            "o que roda",
            "mapeia",
            "mapear superficie",
            "mapear superfície",
            "asset discovery",
            "fingerprinting",
            "tecnologias",
            "tech detect",
            "passive recon",
            "recon passivo",
        ),
    ),
    AttackModule(
        id="dos",
        label="DDoS / rate-limit (bounded)",
        kind="playbook",
        task="rate-limit",
        aggression=3,
        keywords=(
            "ddos",
            "dos",
            "denial of service",
            "stress",
            "flood",
            "rate limit",
            "rate-limit",
            "negacao de servico",
            "negação de serviço",
            "derrubar",
            "derruba",
            "derrubar o servidor",
            "cair o site",
            "fora do ar",
            "sobrecarga",
            "overload",
            "availability",
            "disponibilidade",
            "bombardear",
            "flood de requests",
            "request flood",
            "stress test",
            "teste de carga",
            "load test agressivo",
        ),
    ),
    AttackModule(
        id="brute",
        label="Bruteforce / password spray (capped)",
        kind="tool",
        task="brute_login",
        aggression=3,
        keywords=(
            "bruteforce",
            "brute force",
            "brute-force",
            "forca bruta",
            "força bruta",
            "password spray",
            "credential stuffing",
            "quebrar senha",
            "adivinhar senha",
            "tentar senhas",
            "spray de senha",
            "login spray",
            "wordlist",
            "hydra",
            "senha fraca",
            "weak password",
            "chutar senha",
            "estourar senha",
            "password guessing",
            "credential spray",
        ),
        needs_login_path=True,
    ),
    AttackModule(
        id="auth-bypass",
        label="Password / auth bypass probes",
        kind="playbook",
        task="auth-bypass",
        aggression=2,
        keywords=(
            "bypass de senha",
            "password bypass",
            "auth bypass",
            "authentication bypass",
            "bypass auth",
            "bypass de autenticacao",
            "bypass de autenticação",
            "login bypass",
            "pular login",
            "furar autenticacao",
            "furar autenticação",
            "sem senha",
            "senha vazia",
            "authz bypass",
            "sqli login",
            "sql injection login",
            "contornar login",
            "burlar login",
            "burlar autenticacao",
            "burlar autenticação",
            "skip authentication",
            "break login",
            "auth fail open",
        ),
    ),
    AttackModule(
        id="secrets",
        label="Private tokens / credential leak scan",
        kind="tool",
        task="secrets_scan",
        aggression=1,
        keywords=(
            "tokens privados",
            "token privado",
            "private token",
            "private tokens",
            "api key",
            "apikey",
            "secret key",
            "leak de credenciais",
            "credential leak",
            "credentials",
            "credenciais",
            "vazamento",
            "achar tokens",
            "encontrar tokens",
            "exposed secrets",
            "secrets",
            "segredo",
            "chave privada",
            "private key",
            ".env",
            "jwt leak",
            "bearer leak",
            "pegar token",
            "expor token",
            "hardcoded",
            "chave de api",
            "segredos expostos",
            "credencial vazada",
            "password dump",
            "secret exposure",
            "leaked key",
            "access key",
            "access_token",
        ),
    ),
    AttackModule(
        id="idor",
        label="IDOR / BOLA (A/B sessions)",
        kind="playbook",
        task="idor",
        aggression=2,
        keywords=(
            "idor",
            "bola",
            "broken object",
            "object-level",
            "trocar id",
            "swap id",
            "acesso horizontal",
            "outra conta",
            "outro usuario",
            "outro usuário",
            "cross tenant",
            "cross-tenant",
            "insecure direct object",
            "acessar dado de outro",
            "ver dados de outro",
            "broken access control",
            "controle de acesso",
            "autorizacao quebrada",
            "autorização quebrada",
        ),
        needs_sessions=True,
    ),
    AttackModule(
        id="ssrf",
        label="SSRF probes",
        kind="playbook",
        task="ssrf",
        aggression=2,
        keywords=(
            "ssrf",
            "server-side request",
            "request forgery",
            "metadata",
            "169.254.169.254",
            "fetch interno",
            "url fetch",
            "requisicao server-side",
            "requisição server-side",
            "ssrf interno",
            "cloud metadata",
        ),
    ),
)

# When the operator wants attacks but names nothing specific.
DEFAULT_PACK_IDS: tuple[str, ...] = ("recon", "secrets", "auth-bypass", "brute", "dos")

ATTACK_INTENT = (
    "ataque",
    "ataques",
    "attack",
    "attacks",
    "assault",
    "exploit",
    "explorar",
    "explore",
    "pentest",
    "penetration",
    "hacke",
    "hackear",
    "quebra",
    "quebrar",
    "furar",
    "invadir",
    "comprometer",
    "vulnerab",
    "security test",
    "teste de seguranca",
    "teste de segurança",
    "red team",
    "offensive",
    "faz o que puder",
    "faz o possivel",
    "faz o possível",
    "tudo que der",
    "full test",
    "full assault",
    "campanha",
    "campaign",
    "me entregue",
    "me entrega",
    "resultado",
    "de acordo com o scope",
    "de acordo com o scopo",
    "according to the scope",
    "dentro do scope",
    "in scope",
    "autorizado",
    "bounty",
    # PT-BR colloquial
    "da um jeito",
    "dá um jeito",
    "mete bronca",
    "abre o alvo",
    "trabalha esse alvo",
    "cacada",
    "caçada",
    "hunt",
    "hunting",
    "vai fundo",
    "pode atacar",
    "pode testar",
    "testa tudo",
    "teste tudo",
    "run the suite",
    "go hunt",
    "poke around",
    "find bugs",
    "find vulns",
    "achar falha",
    "achar falhas",
    "achar bug",
    "achar bugs",
)

CAMPAIGN_TRIGGERS = ATTACK_INTENT + (
    "faça ataques",
    "faca ataques",
    "faz ataques",
    "fazer ataques",
    "run attacks",
    "launch attacks",
    "deliver the result",
    "ataque completo",
)


def normalize_text(text: str) -> str:
    """Lowercase, strip accents, collapse punctuation for matching."""
    text = text.lower().replace("scopo", "scope")
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[^\w\s./:-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _module_by_id() -> dict[str, AttackModule]:
    return {m.id: m for m in MODULES}


def score_module(norm: str, mod: AttackModule) -> float:
    """Higher = better match. Keyword substring + token overlap."""
    score = 0.0
    for kw in mod.keywords:
        nkw = normalize_text(kw)
        if not nkw:
            continue
        if nkw in norm:
            # Longer phrases weigh more
            score += 2.0 + min(len(nkw), 40) / 20.0
            continue
        # Token overlap for multi-word keywords
        k_tokens = set(nkw.split())
        if len(k_tokens) >= 2:
            t_tokens = set(norm.split())
            overlap = k_tokens & t_tokens
            if len(overlap) >= max(1, len(k_tokens) - 1):
                score += 1.2 * (len(overlap) / len(k_tokens))
    # Whole-module id as token
    if re.search(rf"(?<![a-z0-9]){re.escape(mod.id)}(?![a-z0-9])", norm):
        score += 3.0
    return score


def has_attack_intent(text: str) -> bool:
    norm = normalize_text(text)
    if any(normalize_text(t) in norm for t in ATTACK_INTENT):
        return True
    # Imperative hunting verbs + host-ish signal often means campaign
    if re.search(
        r"\b(testa|teste|testar|scan|scane|probe|fuzz|valida|validar|checa|checar)\b",
        norm,
    ):
        return True
    return False


def detect_campaign_modules(text: str, *, min_score: float = 1.5) -> list[AttackModule]:
    """Score-based module pick; empty if nothing crosses the threshold."""
    # Explicit router annotation wins
    m = re.search(r"\[routed modules:\s*([^\]]+)\]", text, re.I)
    if m:
        by_id = _module_by_id()
        ids = [x.strip() for x in m.group(1).replace(",", " ").split() if x.strip()]
        return [by_id[i] for i in ids if i in by_id]

    norm = normalize_text(text)
    scored: list[tuple[float, AttackModule]] = []
    for mod in MODULES:
        s = score_module(norm, mod)
        if s >= min_score:
            scored.append((s, mod))
    scored.sort(key=lambda x: (-x[0], x[1].id))
    hit_ids = {m.id for _, m in scored}
    return [m for m in MODULES if m.id in hit_ids]


def resolve_modules(text: str) -> tuple[list[AttackModule], bool]:
    """Return (modules, used_default_pack).

    Always returns at least the default pack when attack intent is present,
    so paraphrases still produce a real campaign instead of an empty refusal.
    """
    hits = detect_campaign_modules(text)
    if hits:
        return hits, False
    if has_attack_intent(text) or is_campaign_prompt(text, modules_only=False):
        by_id = _module_by_id()
        pack = [by_id[i] for i in DEFAULT_PACK_IDS if i in by_id]
        return pack, True
    return [], False


def is_campaign_prompt(text: str, *, modules_only: bool = True) -> bool:
    norm = normalize_text(text)
    if any(normalize_text(t) in norm for t in CAMPAIGN_TRIGGERS):
        return True
    if has_attack_intent(text):
        return True
    if modules_only:
        return len(detect_campaign_modules(text)) >= 1
    return False


def extract_login_path(text: str) -> str:
    m = re.search(r"(?:login|signin|auth)\s+(?:path|url|em|at|em)\s+(\S+)", text, re.I)
    if m:
        return m.group(1).strip(".,;\"'")
    m = re.search(r"(https?://\S+/(?:login|signin|auth|session)\S*)", text, re.I)
    if m:
        return m.group(1).rstrip(".,;\"'")
    return "/login"


def report_markdown(host: str, rows: list[dict], *, fallback_note: str = "") -> str:
    lines = [
        f"# Campaign results — `{host}`",
        "",
    ]
    if fallback_note:
        lines.extend([f"> {fallback_note}", ""])
    lines.extend(
        [
            "| Module | Status | Summary |",
            "| --- | --- | --- |",
        ]
    )
    for row in rows:
        summary = (row.get("summary") or "").replace("|", "/")[:160]
        lines.append(
            f"| {row.get('label') or row.get('id')} | **{row.get('status')}** | {summary} |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append(
        "- DDoS module is a **bounded** rate-limit probe (not volumetric flood)."
    )
    lines.append("- Bruteforce is **capped** (tiny wordlist); needs SCOPE level-3 or `/force`.")
    lines.append("- Secrets findings are pattern matches — confirm impact before reporting.")
    lines.append(
        "- Vague prompts use a **default hunt pack** (recon/secrets/auth-bypass/brute/dos) "
        "so the bot still finishes instead of refusing."
    )
    lines.append("")
    return "\n".join(lines)
