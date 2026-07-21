# Red Team / Offensive Security - backlog de estudo

Status: iniciado em 2026-07-15.

Regra desta trilha:
- Nao marcar fonte como **DEEP** sem ler a pagina principal e subpastas/artigos relevantes.
- Repos grandes devem ser clonados ou inventariados antes da sintese.
- Blogs devem ser estudados por categorias/artigos, nao so pela home.
- Conteudo de C2, implants, evasion, dumping, persistence e lateral movement deve ser salvo como raciocinio, pre-condicoes, impacto e limites de uso, nao como playbook operacional fora de escopo.

## Repos do lote

| Fonte | Status | Nota |
|-------|--------|------|
| `S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet` | **DEEP 2026-07-15** | `red-team/active-directory-exploitation-cheatsheet.md` |
| `infosecn1nja/Red-Teaming-Toolkit` | lido/inventariado 2026-07-15 | README completo; catalogo por fases; nao DEEP de cada ferramenta linkada |
| `A-poc/RedTeam-Tools` | em andamento 2026-07-15 | README grande inventariado por headings; precisa leitura por blocos |
| `samratashok/nishang` | lido/inventariado 2026-07-15 | README completo + arvore de scripts; uso restrito a lab/escopo explicito |
| `mgeeky/Penetration-Testing-Tools` | lido/inventariado 2026-07-15 | README principal + sub-READMEs principais; web/reencode/XXE uteis para bounty |
| `bluscreenofjeff/Red-Team-Infrastructure-Wiki` | lido/inventariado 2026-07-15 | README completo; infra/OPSEC/lab, nao bounty web comum |
| `bL34cHig0/Pentest-Resources-Cheat-Sheets` | lido/inventariado 2026-07-15 | Agregador; README completo |
| `franckferman/SecSheets` | lido/inventariado 2026-07-15 | README completo; site externo ainda pendente |
| `redcanaryco/atomic-red-team` | inventariado 2026-07-15 | README + 354 YAMLs listados; leitura por tecnica ainda pendente |

## Blogs / sites do lote

| Fonte | Status | Como estudar |
|-------|--------|--------------|
| SpecterOps blog/training | trilha principal consolidada 2026-07-15 | Ver `specterops-corpus-map.md`, `specterops-identity-trust-token-track.md` e `specterops-identity-trust-token-track-2.md`; proximo bloco e AI/LLM ou OpenGraph/collectors |
| Bishop Fox Labs/blog | trilhas modernas consolidadas 2026-07-15 | Ver `bishopfox-research-map.md`, `bishopfox-modern-method-track.md`, `bishopfox-cloud-attack-paths.md`, `bishopfox-advisories-ai-mcp.md` |
| Cobalt Strike official blog | corpus mapeado + trilhas prioritarias consolidadas 2026-07-15 | Ver `cobaltstrike-corpus-map.md` e `cobaltstrike-priority-posts.md`; Cloudflare impediu DEEP por post via curl |
| MITRE ATT&CK | dump + familias prioritarias consolidadas 2026-07-15 | Ver `mitre-attack-atomic-red-team.md` e `mitre-atomic-technique-families.md` |
| Atomic Red Team site | indice aberto 2026-07-15 | Usar como lab/validacao controlada, nao contra alvo real |
| Falcon Feeds | consolidado 2026-07-15 | Ver `falconfeeds-threat-intel-track.md`; usar para contexto/priorizacao, nao caca cega |
| OffSec blog | consolidado 2026-07-15 | Ver `offsec-ai-threat-track.md`; foco AI/web/threat/supply chain |
| Black Hat archives | mapa real pronto 2026-07-15 | Ver `blackhat-archives-map.md`; captura via navegador/CDP apos anti-bot, proxima fase e entrar nos schedules por trilha |
| DEF CON archives | mapa + trilhas recentes consolidadas 2026-07-15 | Ver `defcon-archives-map.md` e `defcon-recent-tracks.md` |

## Ordem sugerida

1. SpecterOps por trilha: trusts, token abuse, hybrid identity, BloodHound/OpenGraph, AI workflow.
2. Black Hat por `USA/Europe/Asia` recentes quando o operador retomar essa fonte.
3. RedTeam-Tools leitura por blocos do README, se ainda for necessario.

Nota de progresso detalhada:
- `red-team/red-team-resources-session-2026-07-15.md`
