# Subdomain takeover — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel tipico: enum+fingerprint **1**; claim do recurso so se policy permitir (ainda cuidadoso).

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| HackTricks domain-subdomain-takeover | CNAME dangling; tools; wildcard CNAME→GitHub amplifica; impacto cookie/CORS/OAuth/CSP/CSRF SameSite/MX/NS |
| WSTG-CONF-10 | Enum→fingerprint→manual; S3/Azure/GCP; dig+curl; nao claim sem necessidade |
| OWASP Subdomain Takeover Prevention CS | Mecanica; tabela high-risk (S3, EB, Azure, GH Pages, Heroku, Shopify, Netlify, Fastly, Zendesk…); fingerprints; CloudFront/NS condicionais; MX→DV cert |
| HackerOne Guide 2.0 (EdOverflow) | GoHire exemplo; can-i-take-over-xyz; Okta seguro (TXT challenge); nuclei templates; PoC em path oculto; impacto cookie/CORS/OAuth/CSP; nao reportar “potential” sem claim/prova |
| Nuclei locais | ~73 YAML em `http/takeovers/` + `dns/azure-takeover-detection`, `elasticbeanstalk-takeover` |
| Guia study 4.6 + VRT | Misconfigured DNS / Subdomain Takeover **P3** (sobe com cookie scope / host critico) |
| Persona `.cursor/rules/subdomain-takeover.md` | Workflow enum→fingerprint→manual; OPSEC; report sem claim preferido |
| TOOLCHAIN | subfinder/dnsx/httpx/nuclei na VM; subzy/subjack **ausentes** |

## Modelo mental

DNS ainda aponta pra SaaS/cloud; recurso upstream **nao existe / nao e seu** → atacante registra o mesmo nome no provedor → controla conteudo no host da vitima.

```
DNS (CNAME/A/NS/MX) ──▶ provedor ──X── recurso deprovisionado
                              │
                              ▼ (atacante claim)
                         conteudo sob *.vitima.com
```

| Tipo | Impacto relativo |
|------|------------------|
| CNAME → SaaS claimavel | Classico (GH Pages, Heroku, S3…) |
| A → IP cloud liberado | Mais raro; IP reatribuivel |
| NS dangling | Zona inteira do sub |
| MX dangling | Email + possivel DV TLS via admin@ |

## Pipeline desta VM

```bash
# 1) Enum (nivel 0–1)
subfinder -d alvo.com -silent -o subs.txt
# amass enum -passive -d alvo.com  # se precisar cobertura extra
# crt.sh / chaos opcional

# 2) Resolve + CNAME
cat subs.txt | dnsx -silent -a -cname -resp -o resolved.txt

# 3) Live HTTP
cat resolved.txt | httpx -silent -o live.txt

# 4) Fingerprint takeover (rate baixo na VM)
nuclei -l live.txt -t external_knowledge/nuclei-templates/http/takeovers/ \
  -c 5 -rl 10 -o nuclei_takeover.txt
nuclei -l resolved.txt -t external_knowledge/nuclei-templates/dns/ \
  -tags takeover -c 5 -rl 10

# 5) Manual OBRIGATORIO
dig +short CNAME sub.alvo.com
curl -si https://sub.alvo.com | head
# Conferir fingerprint em can-i-take-over-xyz (issues GitHub — nao clonado localmente)
```

Ou orquestrar com **reconFTW** (`SUBTAKEOVER` / nuclei ja no fluxo) — ver `reconftw/reconftw.cfg`.

## Fingerprints uteis (CS + nuclei)

| Servico | Sinal HTTP / DNS |
|---------|------------------|
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| AWS S3 | `The specified bucket does not exist` + BucketName |
| Heroku | `No such app` |
| Azure App | `404 Web Site not found` / CNAME azure* + NXDOMAIN (dns template) |
| Fastly | `Fastly error: unknown domain` |
| Netlify | `Not Found - Request ID:` |
| Shopify | `Sorry, this shop is currently unavailable.` |
| Zendesk | `Help Center Closed` |
| Elastic Beanstalk | dns template local |

Falsos positivos: Cloudflare na frente, servico com ownership challenge (Okta), account deleted edge-case (Wix), host == ip checks nos templates nuclei.

## Wildcard CNAME (HT)

Se `*.alvo.com` CNAME pra `user.github.io` (ou similar claimavel), atacante cria pagina e **gera** subdominios arbitrarios que o wildcard aceita. Validar wildcard vs registro explicito.

## Impacto pra argumentar no report (H1 guide)

Nao e so “404 feio”:

1. Cookie scope `.alvo.com` → set/read se nao Secure/HttpOnly/Prefix corretos.
2. CORS que confia em `*.alvo.com`.
3. OAuth `redirect_uri` allowlist frouxa.
4. CSP `script-src` inclui o sub.
5. SameSite: sub controlado = same-site pra CSRF cookies.
6. Phishing + Let’s Encrypt no host legítimo.
7. MX: interceptar reset / DV email.

## PoC etico (H1 / persona)

- Preferir **prova sem claim** se policy aceitar: dig + fingerprint + evidencia que bucket/app nao existe.
- Se claim permitido: pagina **oculta** `/randompath.html` com comentario do
  researcher handle — **nunca** deface no index, sem coletar cookies, sem
  Wayback da PoC se programa nao gosta.
- Remover recurso apos ack.

Nao reportar “potential takeover” sem demonstracao confiavel (H1: programas nao querem chase de FP).

## Nivel

| Acao | Nivel |
|------|-------|
| CT / subfinder passivo / dig | 0–1 |
| httpx + nuclei takeovers | 1 |
| Brute DNS massivo (puredns top1m) | 2 |
| Claim + servir HTML | 1–2 + policy |

## VRT

Subdomain Takeover **P3** default. Cookie session / OAuth / host de login → argumentar P2/P1 com impacto. Sub esquecido sem trafego → P4.

## Ligacao hunting

- Apos qualquer `subfinder` de programa novo: nuclei takeovers **antes** de fuzz profundo.
- X.com: wildcards enormes — filtrar OOS; takeover so em host in-scope.
- Cloud persona se Azure/S3 dominante.

## Fontes

- https://www.hackerone.com/blog/guide-subdomain-takeovers-20
- https://github.com/EdOverflow/can-i-take-over-xyz
- `hacktricks/.../domain-subdomain-takeover.md`
- WSTG-CONF-10
- `CheatSheetSeries/.../Subdomain_Takeover_Prevention_Cheat_Sheet.md`
- `nuclei-templates/http/takeovers/` (~73) + `dns/*takeover*`
- Guia §4.6; VRT Misconfigured DNS
- Persona `subdomain-takeover.md`

## Proxima

Content discovery (paralelo nesta sessao) → hunting ao vivo ou smuggling/cache DEEP.
