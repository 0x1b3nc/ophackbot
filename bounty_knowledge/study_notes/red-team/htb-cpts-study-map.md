# HTB CPTS Study Map — 0x1ceKing/HTB-Certified-Penetration-Testing-Specialist

Data: **2026-07-17**.  
Repo local: `bounty_knowledge/red-team/HTB-Certified-Penetration-Testing-Specialist/`  
Fonte: https://github.com/0x1ceKing/HTB-Certified-Penetration-Testing-Specialist

Status: **mapa + deep nos eixos Web/OSINT/Credential** (aplicável a bounty). Módulos AD/MSF/pivoting mapeados, não DEEP linha-a-linha nesta sessão.

## O que é o material

Compilação de notas/cheatsheets do path **Hack The Box Academy → Certified Penetration Testing Specialist (CPTS)**:

| Pasta | Conteúdo |
|-------|----------|
| `modules/` | 10 módulos Academy (Process, Nmap, Footprinting, Info Gathering Web, Assessments, File Transfers, Shells, Metasploit, Password Attacks, Getting Started) |
| `cheatsheet/` | Quick refs (Nmap, FFUF, Web Proxies, XSS, SQLi, AD, Password, etc.) |
| `wordlists/` | username/password lists + rule de mutação |

~124 Markdown · ~4.5MB. README lista ainda cheatsheets “vazios” (LFI/Upload/PrivEsc/Reporting) — stubs, não arquivos locais.

## Processo CPTS (âncora mental)

Estágios **iterativos** (não círculo rígido que quebra):

1. Pre-Engagement (escopo/RoE)  
2. Information Gathering  
3. Vulnerability Assessment  
4. Exploitation  
5. Post-Exploitation (pillaging / creds)  
6. Lateral Movement  
7. Proof-of-Concept  
8. Post-Engagement (report + cleanup)

Para **bug bounty**: Pre-Engagement = brief/SCOPE; PoC = FINDINGS mínimo; sem lateral em infra fora do escopo.

## Eixos estudados nesta sessão (síntese operacional)

### Information Gathering — Web

- **DNS/subs/CT/vhost** — já alinhado ao nosso Phase1 (subfinder/httpx).
- **Fingerprinting** — banners/headers/`whatweb`/`wafw00f`; no examreg: Kestrel + `Server`, `WWW-Authenticate: ApiKey`.
- **Crawling / Creepy Crawlies** — Burp Spider, ZAP, Scrapy; extrair `js_files`, forms, links (chave para achar onde a API key é injetada).
- **Well-Known URIs** — `/.well-known/*`, OIDC discovery (já testamos MCP; repetir em hosts Learn/exam).
- **Search Engine Discovery / Google Dorking** — `site:`, `filetype:`, `inurl:`, GHDB; caçar `X-API-KEY`, `examregistration-api`, `appsettings`, swagger histórico.
- **Web Archives** — Wayback/CDX/waybackurls: rotas/JS/configs antigos que sumiram do live.
- Cheatsheet Info Gathering: crt.sh, theHarvester, waybackurls, ffuf vhost/dir, aquatone.

### Password / Credential Hunting (adaptado a web/API)

CPTS ensina pillaging pós-shell; para bounty **sem shell**, o análogo é:

| CPTS (host) | Bounty / API key leak |
|-------------|------------------------|
| Configs `.conf/.cnf` com user/pass | JS bundles, `.env` públicos, `appsettings*.json`, Swagger, Postman collections |
| Scripts / source / cron | Repos GitHub, Actions logs, gists, npm packages |
| History / logs | Wayback, proxy history, Referer com `?X-API-KEY=` |
| Browser store | Sessão Learn autenticada (Burp) revelando header |
| Default/reuse (Hydra) | **Não** brute massivo de API key em bounty GitHub; só defaults documentados / stuffing leve se brief permitir |

Nota crítica CPTS: API key em **query** (`in=header_or_query_params`) = risco clássico de leak em logs, analytics, Referer — priorizar dorks/archives por URL com `X-API-KEY=`.

### FFUF / Web Proxies

- Dir/ext/param/vhost fuzz com filtro de tamanho (`-fs`/`-fc`); wordlists SecLists.
- Burp: Match/Replace UA, Intruder controlado, Spider → JS inventory.
- Já aplicado em examreg: ffuf rate-limited → inventário `/api/v1/*`.

### Fora do foco imediato (mapeado)

Nmap profundo, Footprinting SMB/SNMP/etc., Metasploit, Shells, File Transfers, AD enum/PtH/PtT, Nessus/OpenVAS — úteis em engajamento interno/lab; **não** prioridade no track GitHub unauth atual.

## Aplicacao direta

Hipotese CPTS-style: segredo/API key geralmente aparece em artefato de
**Information Gathering** publico ou em sessao legitima, nao via brute.

Ordem sugerida:

1. OSINT/dorks: host + nome da API + `api_key`/`X-API-KEY` + `appsettings`.
2. Archives: CDX/Wayback e assets historicos do dominio autorizado.
3. JS/crawl autenticado: Burp no fluxo permitido do operador.
4. Integrações: docs publicas, Postman, OpenAPI, SDKs.
5. So entao validar a key com minimo impacto e medir authz/tenant boundary.

## Limites deste deep

- Não substitui Academy oficial HTB (labs/skills assessments).
- Cheatsheets incompletos no README não foram inventados.
- AD/PrivEsc: usar nota SpecterOps / AD cheatsheet já no workspace se precisar depois.

## Refs cruzadas workspace

- `study_notes/recon/content-discovery.md`
- `study_notes/web-vulns/auth-session.md`
- Aplicar apenas em alvos autorizados e registrar evidencias em `targets/<program>/`.
