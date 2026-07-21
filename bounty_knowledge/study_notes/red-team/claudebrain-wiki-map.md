# ClaudeBrain wiki — mapa de uso (HexStrike)

**Data:** 2026-07-17  
**Fonte:** [Encod3d-Sec/ClaudeBrain](https://github.com/Encod3d-Sec/ClaudeBrain)  
**Local:** `bounty_knowledge/ClaudeBrain/`  
**Postura:** conhecimento ofensivo local. Não instalar hooks/MCP/CLAUDE.md deste repo como orquestrador Cursor.

## O que tem valor imediato

| Área | Path | Quando abrir |
|------|------|----------------|
| Técnicas web | `wiki/techniques/web/` | IDOR, SSRF, XSS, auth, smuggling, cache… |
| AD / internal | `wiki/techniques/active-directory/` | Engajamento enterprise / lab AD |
| Cloud | `wiki/techniques/cloud/` | AWS/Azure/GCP paths |
| Red-team ops | `wiki/techniques/red-team/` | Lateral, evasion, methodology |
| Payloads | `wiki/payloads/` | Arsenal por classe |
| Tools | `wiki/tools/` | Notas nmap/ffuf/nuclei/BloodHound/… |
| Cheatsheets | `wiki/cheatsheets/` | Lookup rápido |
| Hunt playbooks | `skills/hunt/hunt-*/SKILL.md` | Checklist por vuln (wiki-first) |

Índices: `wiki/index.md`, `wiki/moc.md`, `wiki/overview.md`.  
Contrato local: `ClaudeBrain/USE_IN_HEXSTRIKE.md`.

## Hunt skills úteis em bounty (ler SKILL.md)

`hunt-api`, `hunt-auth`, `hunt-ssrf`, `hunt-sqli`, `hunt-xss`, `hunt-bizlogic`, `hunt-smuggling`, `hunt-cache`, `hunt-secrets`, `hunt-upload`, `hunt-deserialization`, `hunt-rce`, `hunt-cicd`, `hunt-ad`, `hunt-m365`, `hunt-mcp`, `triage`, `evidence`, `disclosure`.

## Relação com o que já temos

- Continua valendo: `study_notes` (síntese DEEP), HackTricks, PAT, WSTG, Bug-Bounty-Agents.
- ClaudeBrain **complementa** (cobertura AD/cloud/payloads densa + hunt skills uniformes).
- Em dúvida de hipótese: study_notes da classe → página wiki ClaudeBrain → ataque concreto com TOOLCHAIN.

## Atualizar

```bash
cd external_knowledge/ClaudeBrain && git pull --ff-only
# ou: bounty_knowledge/update.sh
```

## Não marcar DEEP

Este mapa é inventário + rota de uso. DEEP continua sendo nota sintetizada por classe em `study_notes/web-vulns/` etc., não “li o index inteiro”.
