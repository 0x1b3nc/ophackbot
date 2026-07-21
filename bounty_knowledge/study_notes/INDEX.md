# Study notes INDEX

Base gerada a partir de estudo local e leitura de fontes públicas como PortSwigger,
OWASP API Top 10, VRT, Bugcrowd University, TBHM e PayloadsAllTheThings.

Template de cada nota: O que e / Onde / Bypass / PoC / Nivel 0-3 / VRT / Fontes.

Regra de uso obrigatoria: antes de concluir plano, script, report, severidade ou proximo hunting step, consultar [STUDY_MATERIAL_ROUTING.md](STUDY_MATERIAL_ROUTING.md) e abrir as notas correspondentes a superficie/bug class da tarefa.

| Nota | Categoria | Status |
|------|-----------|--------|
| [idor-bac.md](web-vulns/idor-bac.md) | Authz / BOLA | **DEEP 2026-07-12** (PortSwigger+labs, OWASP API1/3, WSTG, HackTricks, Vickie Li, BC Univ PDF, PAT, VRT) |
| [auth-session.md](web-vulns/auth-session.md) | JWT / OAuth / reset | **DEEP 2026-07-12** (PortSwigger JWT labs+alg confusion+OAuth, HackTricks, PAT, WSTG, OAuth2 CS, VRT) |
| [ssrf.md](web-vulns/ssrf.md) | SSRF | **DEEP 2026-07-12** (PortSwigger+labs+blind, Vickie bypass, HackTricks, PAT, WSTG, API7, BC Univ PDF, VRT) |
| [injection.md](web-vulns/injection.md) | SQLi/NoSQL/CMDi/SSTI/XXE | **DEEP 2026-07-12** (PS SQLi+NoSQL+CMDi+SSTI+XXE, PAT×5, WSTG, VRT; BC Univ PDFs locais) |
| [race-conditions.md](web-vulns/race-conditions.md) | Race / logica | **DEEP 2026-07-12** (PortSwigger+lab limit overrun+metodologia, HT, PAT, VRT, guia 4.5) |
| [client-side.md](web-vulns/client-side.md) | DOM XSS / PP / postMessage | **DEEP 2026-07-12** + delta 2026-07-15 (`targetOrigin` bypass via IPv4 normalization; CTBB/WHATWG) |
| [owasp-api-top10.md](api-security/owasp-api-top10.md) | API Top 10 2023 | parcial (tabela + uso) |
| [graphql-smuggling-cache.md](api-security/graphql-smuggling-cache.md) | GraphQL | **DEEP GraphQL 2026-07-12** (PS+4 labs, HT, PAT, WSTG, CS, VRT) |
| [smuggling-cache.md](api-security/smuggling-cache.md) | Smuggling / cache poison+deception | **DEEP 2026-07-12** (PS smuggling+finding+cache+design flaws, HT desync+Gotta Cache, WSTG-16, VRT) |
| [mobile-maui-banking-api.md](api-security/mobile-maui-banking-api.md) | Mobile banking / MAUI API | **2026-07-14** (metodo: MAUI/.NET, cert APIs, pre-auth, XS2A, WebView bridge, no-go) |
| [promptfoo-lm-security-db.md](ai-security/promptfoo-lm-security-db.md) | AI / LLM security | backlog tecnico 2026-07-20 (Promptfoo LM Security DB; 931 entries; usar para agentic/RAG/MCP/tool-calling hunting, nao DEEP ainda) |
| [awesome-llms-vulnerability-detection.md](ai-security/awesome-llms-vulnerability-detection.md) | AI / vulnerability detection | **DEEP INDEX PASS 2026-07-20** (repo mapeado como roteador operacional; LLMs para function/repo-level vuln detection, agentic scanners, CPG/dataflow, false-positive triage; papers individuais nao marcados DEEP) |
| [subdomain-takeover.md](recon/subdomain-takeover.md) | Takeover | **DEEP 2026-07-12** (HT, WSTG-CONF-10, OWASP CS, H1 Guide 2.0, nuclei ~73, VRT P3, persona) |
| [content-discovery.md](recon/content-discovery.md) | Recon / discovery | **DEEP 2026-07-12** (TBHM 01–03, TOOLCHAIN, guia §5–7, awesome, reconFTW, SecLists, persona) |
| [active-directory-exploitation-cheatsheet.md](red-team/active-directory-exploitation-cheatsheet.md) | Red team / Active Directory | **DEEP 2026-07-15** (S1ckB0y1337 repo completo: README 1370 linhas; enum, ACL, delegation, ADCS, persistence, cross-forest; uso apenas em escopo enterprise/lab) |
| [specterops-corpus-map.md](red-team/specterops-corpus-map.md) | Red team / SpecterOps | **2026-07-15** (corpus completo mapeado: 197 posts + 32 resources; temas dominantes, prioridades de leitura, sem marcar DEEP por artigo ainda) |
| [specterops-identity-trust-token-track.md](red-team/specterops-identity-trust-token-track.md) | Red team / SpecterOps | **2026-07-15** (trilha tecnica consolidada: AD trusts, Entra SSO cookies e Azure API permission abuse) |
| [specterops-identity-trust-token-track-2.md](red-team/specterops-identity-trust-token-track-2.md) | Red team / SpecterOps | **2026-07-15** (trilha tecnica consolidada II: service principal abuse, Seamless SSO, AORTA e SCCM/Entra) |
| [bishopfox-research-map.md](red-team/bishopfox-research-map.md) | Red team / Bishop Fox | **2026-07-15** (research sitemap legado + leitura do Labs/Blog atual; temas, ferramentas e prioridades, ainda sem DEEP por artigo) |
| [bishopfox-modern-method-track.md](red-team/bishopfox-modern-method-track.md) | Red team / Bishop Fox | **2026-07-15** (trilha moderna consolidada: ServiceNow public exposure, favicon intelligence, AI-assisted validation, MCP authz e LLM patch diffing) |
| [bishopfox-cloud-attack-paths.md](red-team/bishopfox-cloud-attack-paths.md) | Red team / Bishop Fox | **2026-07-15** (subbloco cloud consolidado: GCP IAM inheritance, service accounts, attack paths, data plane e reuse de identities entre ambientes) |
| [bishopfox-advisories-ai-mcp.md](red-team/bishopfox-advisories-ai-mcp.md) | Red team / Bishop Fox | **2026-07-15** (advisories tecnicos + AI/MCP: confused deputy, SSRF/token passthrough, excessive agency, auth bypass e chain de impacto) |
| [mitre-attack-atomic-red-team.md](red-team/mitre-attack-atomic-red-team.md) | Red team / MITRE ATT&CK + Atomic | **2026-07-15** (dump Enterprise local + repo Atomic local; contagens, familias uteis, regra de uso em bounty/enterprise/lab) |
| [mitre-atomic-technique-families.md](red-team/mitre-atomic-technique-families.md) | Red team / MITRE ATT&CK + Atomic | **2026-07-15** (familias T1552/T1098/T1078/T1550/T1021/T1484 consolidadas com Atomic local) |
| [cobaltstrike-corpus-map.md](red-team/cobaltstrike-corpus-map.md) | Red team / Cobalt Strike | **2026-07-15** (blog oficial mapeado: 277 posts, 28 paginas, topicos/autor dominantes e prioridades de leitura) |
| [cobaltstrike-priority-posts.md](red-team/cobaltstrike-priority-posts.md) | Red team / Cobalt Strike | **2026-07-15** (trilhas prioritarias: REST API, AI, Beacon instrumentation, BOF/scripting/integrations; Cloudflare impediu DEEP por post) |
| [defcon-archives-map.md](red-team/defcon-archives-map.md) | Red team / DEF CON | **2026-07-15** (arquivo estrutural mapeado: 37 URLs locais, secoes por edicao e fluxo de uso por trilha) |
| [defcon-recent-tracks.md](red-team/defcon-recent-tracks.md) | Red team / DEF CON | **2026-07-15** (trilhas recentes 31/32/33: web, cloud, identity, AI, supply chain, hardware/mobile) |
| [blackhat-archives-map.md](red-team/blackhat-archives-map.md) | Red team / Black Hat | **2026-07-15** (hub real de archives mapeado via navegador/CDP: 237 links, regioes/anos e prioridades de aprofundamento) |
| [offsec-ai-threat-track.md](red-team/offsec-ai-threat-track.md) | Red team / OffSec | **2026-07-15** (AI pentest, shadow AI, web methodology, bug bounty, threat intel e supply chain) |
| [falconfeeds-threat-intel-track.md](red-team/falconfeeds-threat-intel-track.md) | Red team / Falcon Feeds | **2026-07-15** (threat intelligence, dark web/ransomware context, MCP FalconFeeds e uso como priorizacao) |
| [claudebrain-wiki-map.md](red-team/claudebrain-wiki-map.md) | Red team / ClaudeBrain wiki | **2026-07-17** (Encod3d-Sec/ClaudeBrain clonado: wiki ~500 págs + hunt skills; uso conhecimento-only, sem harness Claude) |
| [htb-cpts-study-map.md](red-team/htb-cpts-study-map.md) | Red team / HTB CPTS | **2026-07-17** (0x1ceKing CPTS notes: processo + Web OSINT/archives/dorks + credential hunting; usar apenas com escopo autorizado) |
| [resource-backlog.md](red-team/resource-backlog.md) | Red team / Offensive Security | iniciado 2026-07-15 (backlog dos repos/blogs; nao marcar DEEP sem ler subpastas/artigos relevantes) |
| [red-team-resources-session-2026-07-15.md](red-team/red-team-resources-session-2026-07-15.md) | Red team / Offensive Security | **lote fechado 2026-07-15** (fontes solicitadas consolidadas por trilha; limites de DEEP total registrados) |

## Cadencia

Uma classe **deep** por sessao (ou paralelo quando pedido): ler fontes de verdade, logar na nota, so entao marcar DEEP. Esqueleto != estudado.

**Sessao de estudo do guia: FECHADA 2026-07-12.** Todas as notas de web-vulns + GraphQL + smuggling/cache + recon do INDEX estao DEEP (owasp-api-top10 continua parcial/tabela).

Ultima deep: **Smuggling + Cache** (2026-07-12). Proximo modo: hunting (nao mais deep do guia).


## Fontes externas

Este kit não versiona corpora terceiros completos. Use
`scripts/import_knowledge_sources.sh` para criar `external_knowledge/` local com
as fontes públicas recomendadas.
