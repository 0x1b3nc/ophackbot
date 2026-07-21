# Study Notes INDEX

My notes from local study plus public sources: PortSwigger, OWASP API Top 10,
VRT, Bugcrowd University, TBHM, PayloadsAllTheThings.

Note template I use: What it is / Where / Bypass / PoC / Level 0-3 / VRT / Sources.

Rule for me: before I settle a plan, script, report, severity, or next hunting
step, I open [STUDY_MATERIAL_ROUTING.md](STUDY_MATERIAL_ROUTING.md) and the notes
for that surface/bug class.

| Note | Category | Status |
|------|-----------|--------|
| [idor-bac.md](web-vulns/idor-bac.md) | Authz / BOLA | **DEEP 2026-07-12** (PortSwigger+labs, OWASP API1/3, WSTG, HackTricks, Vickie Li, BC Univ PDF, PAT, VRT) |
| [auth-session.md](web-vulns/auth-session.md) | JWT / OAuth / reset | **DEEP 2026-07-12** (PortSwigger JWT labs+alg confusion+OAuth, HackTricks, PAT, WSTG, OAuth2 CS, VRT) |
| [ssrf.md](web-vulns/ssrf.md) | SSRF | **DEEP 2026-07-12** (PortSwigger+labs+blind, Vickie bypass, HackTricks, PAT, WSTG, API7, BC Univ PDF, VRT) |
| [injection.md](web-vulns/injection.md) | SQLi/NoSQL/CMDi/SSTI/XXE | **DEEP 2026-07-12** (PS SQLi+NoSQL+CMDi+SSTI+XXE, PAT×5, WSTG, VRT; BC Univ PDFs local) |
| [race-conditions.md](web-vulns/race-conditions.md) | Race / logic | **DEEP 2026-07-12** (PortSwigger+lab limit overrun+methodology, HT, PAT, VRT, guide 4.5) |
| [client-side.md](web-vulns/client-side.md) | DOM XSS / PP / postMessage | **DEEP 2026-07-12** + delta 2026-07-15 (`targetOrigin` bypass via IPv4 normalization; CTBB/WHATWG) |
| [owasp-api-top10.md](api-security/owasp-api-top10.md) | API Top 10 2023 | partial (table + usage) |
| [graphql-smuggling-cache.md](api-security/graphql-smuggling-cache.md) | GraphQL | **DEEP GraphQL 2026-07-12** (PS+4 labs, HT, PAT, WSTG, CS, VRT) |
| [smuggling-cache.md](api-security/smuggling-cache.md) | Smuggling / cache poison+deception | **DEEP 2026-07-12** (PS smuggling+finding+cache+design flaws, HT desync+Gotta Cache, WSTG-16, VRT) |
| [mobile-maui-banking-api.md](api-security/mobile-maui-banking-api.md) | Mobile banking / MAUI API | **2026-07-14** (method: MAUI/.NET, cert APIs, pre-auth, XS2A, WebView bridge, no-go) |
| [promptfoo-lm-security-db.md](ai-security/promptfoo-lm-security-db.md) | AI / LLM security | tech backlog 2026-07-20 (Promptfoo LM Security DB; 931 entries; for agentic/RAG/MCP/tool-calling hunting, not DEEP yet) |
| [awesome-llms-vulnerability-detection.md](ai-security/awesome-llms-vulnerability-detection.md) | AI / vulnerability detection | **DEEP INDEX PASS 2026-07-20** (repo mapped as operational router; LLMs for function/repo-level vuln detection, agentic scanners, CPG/dataflow, FP triage; individual papers not marked DEEP) |
| [subdomain-takeover.md](recon/subdomain-takeover.md) | Takeover | **DEEP 2026-07-12** (HT, WSTG-CONF-10, OWASP CS, H1 Guide 2.0, nuclei ~73, VRT P3, persona) |
| [content-discovery.md](recon/content-discovery.md) | Recon / discovery | **DEEP 2026-07-12** (TBHM 01–03, TOOLCHAIN, guide §5–7, awesome, reconFTW, SecLists, persona) |
| [active-directory-exploitation-cheatsheet.md](red-team/active-directory-exploitation-cheatsheet.md) | Red team / Active Directory | **DEEP 2026-07-15** (S1ckB0y1337 full repo: README 1370 lines; enum, ACL, delegation, ADCS, persistence, cross-forest; enterprise/lab scope only) |
| [specterops-corpus-map.md](red-team/specterops-corpus-map.md) | Red team / SpecterOps | **2026-07-15** (full corpus mapped: 197 posts + 32 resources; themes, reading priorities; not DEEP per article yet) |
| [specterops-identity-trust-token-track.md](red-team/specterops-identity-trust-token-track.md) | Red team / SpecterOps | **2026-07-15** (consolidated track: AD trusts, Entra SSO cookies, Azure API permission abuse) |
| [specterops-identity-trust-token-track-2.md](red-team/specterops-identity-trust-token-track-2.md) | Red team / SpecterOps | **2026-07-15** (track II: service principal abuse, Seamless SSO, AORTA, SCCM/Entra) |
| [bishopfox-research-map.md](red-team/bishopfox-research-map.md) | Red team / Bishop Fox | **2026-07-15** (legacy research sitemap + current Labs/Blog; themes, tools, priorities; not DEEP per article) |
| [bishopfox-modern-method-track.md](red-team/bishopfox-modern-method-track.md) | Red team / Bishop Fox | **2026-07-15** (modern track: ServiceNow public exposure, favicon intel, AI-assisted validation, MCP authz, LLM patch diffing) |
| [bishopfox-cloud-attack-paths.md](red-team/bishopfox-cloud-attack-paths.md) | Red team / Bishop Fox | **2026-07-15** (cloud block: GCP IAM inheritance, service accounts, attack paths, data plane, identity reuse) |
| [bishopfox-advisories-ai-mcp.md](red-team/bishopfox-advisories-ai-mcp.md) | Red team / Bishop Fox | **2026-07-15** (advisories + AI/MCP: confused deputy, SSRF/token passthrough, excessive agency, auth bypass, impact chains) |
| [mitre-attack-atomic-red-team.md](red-team/mitre-attack-atomic-red-team.md) | Red team / MITRE ATT&CK + Atomic | **2026-07-15** (local Enterprise dump + Atomic repo; counts, useful families, bounty/enterprise/lab usage rule) |
| [mitre-atomic-technique-families.md](red-team/mitre-atomic-technique-families.md) | Red team / MITRE ATT&CK + Atomic | **2026-07-15** (T1552/T1098/T1078/T1550/T1021/T1484 families with local Atomic) |
| [cobaltstrike-corpus-map.md](red-team/cobaltstrike-corpus-map.md) | Red team / Cobalt Strike | **2026-07-15** (official blog mapped: 277 posts, 28 pages, topics/authors, reading priorities) |
| [cobaltstrike-priority-posts.md](red-team/cobaltstrike-priority-posts.md) | Red team / Cobalt Strike | **2026-07-15** (priority tracks: REST API, AI, Beacon instrumentation, BOF/scripting/integrations; Cloudflare blocked DEEP per post) |
| [defcon-archives-map.md](red-team/defcon-archives-map.md) | Red team / DEF CON | **2026-07-15** (archive structure mapped: 37 local URLs, sections by edition, track usage flow) |
| [defcon-recent-tracks.md](red-team/defcon-recent-tracks.md) | Red team / DEF CON | **2026-07-15** (recent tracks 31/32/33: web, cloud, identity, AI, supply chain, hardware/mobile) |
| [blackhat-archives-map.md](red-team/blackhat-archives-map.md) | Red team / Black Hat | **2026-07-15** (archives hub mapped via browser/CDP: 237 links, regions/years, deepen priorities) |
| [offsec-ai-threat-track.md](red-team/offsec-ai-threat-track.md) | Red team / OffSec | **2026-07-15** (AI pentest, shadow AI, web methodology, bug bounty, threat intel, supply chain) |
| [falconfeeds-threat-intel-track.md](red-team/falconfeeds-threat-intel-track.md) | Red team / Falcon Feeds | **2026-07-15** (threat intel, dark web/ransomware context, MCP FalconFeeds, prioritization use) |
| [claudebrain-wiki-map.md](red-team/claudebrain-wiki-map.md) | Red team / ClaudeBrain wiki | **2026-07-17** (Encod3d-Sec/ClaudeBrain cloned: wiki ~500 pages + hunt skills; knowledge-only, no Claude harness) |
| [htb-cpts-study-map.md](red-team/htb-cpts-study-map.md) | Red team / HTB CPTS | **2026-07-17** (0x1ceKing CPTS notes: process + Web OSINT/archives/dorks + credential hunting; authorized scope only) |
| [resource-backlog.md](red-team/resource-backlog.md) | Red team / Offensive Security | started 2026-07-15 (repo/blog backlog; don't mark DEEP without reading relevant subpaths/articles) |
| [red-team-resources-session-2026-07-15.md](red-team/red-team-resources-session-2026-07-15.md) | Red team / Offensive Security | **batch closed 2026-07-15** (requested sources consolidated by track; full-DEEP limits logged) |

## Cadence

One **deep** class per session (or parallel when I ask for it): read source-of-truth material, log it in the note, then mark DEEP. Skeleton ≠ studied.

**Guide study session: CLOSED 2026-07-12.** All web-vulns + GraphQL + smuggling/cache + recon notes in this INDEX are DEEP (`owasp-api-top10` still partial/table).

Last deep: **Smuggling + Cache** (2026-07-12). Next mode: hunting (not more guide deep).

## External sources

I don't vendor full third-party corpora in this kit. I use
`scripts/import_knowledge_sources.sh` to build local `external_knowledge/` with
the public sources I recommend.
