# SSRF (Server-Side Request Forgery) — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel tipico: **2** (payload unico + OAST). Port scan interno amplo = **3**.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger SSRF (pagina principal, sessao anterior + reforco) | stockApi pattern; trust localhost; backend privado; blacklist/whitelist; open redirect chain; Referer analytics; partial URL; XXE→SSRF |
| PortSwigger Blind SSRF | OAST obrigatorio; DNS sem HTTP = filtro de rede; blind sweep interno; client-side HTTP stack RCE via resposta maliciosa |
| Lab: basic SSRF localhost | `stockApi=http://localhost/admin` → delete carlos |
| Lab: basic SSRF backend | Intruder `192.168.0.X:8080/admin` → achar host 200 → delete |
| Lab: blacklist filter | `127.1` bypass IP; double-URL-encode `a` em admin (`%2561`) |
| Lab: open redirect bypass | stockApi so aceita host local; `/product/nextProduct?path=http://192.168.0.12:8080/admin` seguido pelo checker |
| Lab whitelist | URL 404 nesta sessao; conceito ja no PortSwigger main + Vickie (open redirect / regex fraca) |
| Vickie Li bypass SSRF | Blacklist vs whitelist; redirect proprio; DNS A→127.0.0.1; IPv6; hex/octal/dword/URL/mixed encoding; pensar como o dev implementou o filtro |
| DNS rebinding TOCTOU (H1 #1369312 + H1 SSRF blog) | Validate-then-fetch: 1ª lookup “safe”, 2ª → loopback/RFC1918/metadata. Obrigatorio apos block de IP direto |
| HackTricks SSRF README | OAST tools; protocols file/dict/sftp/tftp/ldap/gopher; curl globbing; Gopherus |
| HackTricks url-format-bypass | `0`, `127.1`, dword `2130706433`, octal, hex, IPv6, nip.io, localtest.me, `@`/`#` parsing |
| HackTricks cloud-ssrf | AWS IMDSv1 GET vs IMDSv2 PUT+token; hop limit; block X-Forwarded-For no token |
| PAT SSRF README + Cloud Instances | Metodologia; filtros; schemes; AWS/GCP/Azure/K8s/Docker URLs |
| WSTG-INPV-19 | Injection points; file://; PDF iframe; bypass list; `@`/`#` |
| OWASP API7:2023 | Webhooks, URL fetch, SSO, preview; cloud/K8s HTTP control planes |
| Bugcrowd University SSRF PDF (18p) | External vs internal; metadata AWS/Ali/GCP/DO/Oracle/Docker/etcd; blacklist module |
| VRT JSON | Secrets P2; data P3; port scan P3/P4; DNS-only / external low P5 |

## Modelo mental

App faz request **no servidor** para URL (ou pedaco de URL) que voce influencia.

| Tipo | Feedback | Como confirmar | Impacto tipico |
|------|----------|----------------|----------------|
| Full-read / reflected | Body/erro da request interna volta | Ver HTML admin / file / JSON | Alto (ACL bypass, secrets) |
| Blind | Sem body | OAST DNS/HTTP (Collaborator, interactsh) | Medio ate encadear |
| Semi-blind | Timing / status / erro diferente | Oraculo de porta aberta | Enum interno |

Confianca classica (PortSwigger): pedido que “vem do localhost” passa ACL que o browser nao passa → `http://localhost/admin` via SSRF vira critico.

## DNS rebinding (server-side SSRF) — checklist operacional

Nao confundir com rebind **no browser** (SOP/IoT). Aqui o **servidor** resolve DNS duas vezes:

```
URL atacante → check(resolve→IP publico OK) → fetch(resolve de novo→127.0.0.1/metadata)
```

| Passo | Acao |
|-------|------|
| 1 | Confirmar sink (`url`, `callback`, `webhook`, `image`, `import`, `avatar`, `og`) |
| 2 | OAST direto (prova de fetch) |
| 3 | IP privado/metadata direto — se block, **nao parar** |
| 4 | Rebind TTL baixo (`rbndr.us` / DNS proprio): safe→internal |
| 5 | Redirect 302 do host controlado → interno (se segue redirect apos check) |
| 6 | Open redirect em host allowlisted |

Mitigacao esperada no alvo: pin do IP no check + request nesse IP (sem 2ª resolucao), ou deny apos re-resolve.

Ref: https://hackerone.com/reports/1369312 · https://www.hackerone.com/blog/how-server-side-request-forgery-ssrf

## Onde aparece (superficie)

- Webhook / SIEM callback (API7 GraphQL mutation com URL)
- Upload por URL / avatar / “import from URL”
- Preview de link / unfurl / oEmbed
- Stock check / proxy / “fetch resource” (`stockApi=`)
- PDF/HTML→PDF (`iframe`/`img`/`url()` → file:// ou interno) — WSTG
- Custom SSO / OAuth icon-uri (exemplo BC Univ Atlassian-style)
- Referer visitado por analytics (blind)
- XML/XXE que resolve entidade externa

## Playbook de confirmacao (ordem)

1. **OAST primeiro** (mesmo se parecer full-read): prova que o server sai.
   - DNS only sem HTTP: outbound DNS liberado, HTTP bloqueado — ainda e sinal.
2. Se full-read: `http://127.1/` → `/admin` ou path conhecido.
3. Bypass blacklist curto (lab + Vickie + HackTricks):
   - `127.1`, `0`, `2130706433`, `0x7f000001`, `0177.0.0.1`
   - `http://[::1]/`, `localtest.me`, `nip.io`
   - Double encoding path (`%2561dmin`)
   - Redirect em host que voce controla
4. Whitelist: open redirect **no dominio permitido** (lab PortSwigger) ou `allowed@evil` / `evil#allowed` se parsers divergem.
5. Cloud metadata **so depois** de OAST e se o alvo parecer cloud:
   - AWS v1: `http://169.254.169.254/latest/meta-data/`
   - AWS v2: precisa PUT token + header — SSRF classico GET muitas vezes **nao** chega
   - GCP: `http://169.254.169.254/computeMetadata/v1/` (+ header `Metadata-Flavor: Google` em alguns paths)
   - Ali: `100.100.100.200`, Oracle `192.0.0.192`, Docker `127.0.0.1:2375`, etcd `:2379`
6. Protocolos avancados (se client for curl/lib com schemes): `file://`, `gopher://` (RCE em servicos internos via Gopherus) — so com impacto claro e escopo ok.

## Labs (o que a solucao ensina)

| Lab | Licao |
|-----|-------|
| Localhost admin | Trust boundary: SSRF = “sou o server” |
| Backend 192.168.0.X | Full-read permite Intruder de faixa pequena |
| Blacklist | Representacao IP + encode de path |
| Open redirect | Filtro de host != filtro de destino final se follow redirect |

## Severidade (VRT)

- Internal **secrets** (creds metadata, keys): **P2**
- Internal **data** exposure: **P3**
- Internal port **service** scan com info: **P3**
- Presence only / port scan only: **P4**
- External DNS only / low impact external: **P5**

H1: full-read metadata ou admin interno → High/Critical narrativo; blind OAST sem mais nada → Low/Medium.

## Nivel de agressividade (nosso framework)

| Acao | Nivel |
|------|-------|
| 1 URL OAST | 2 |
| Poucos bypasses localhost | 2 |
| Intruder /16 interno | 3 (evitar na maioria; exige autorizacao clara) |
| DoS via SSRF loops | proibido sem policy |

## Aplicacao em hunting

- SSRF puntual em um campo URL/webhook/import = nivel 2.
- Nao varrer faixas internas grandes sem policy explicita.
- Sempre: OAST antes de metadata; IMDSv2 pode matar o path AWS “facil”.

## Remediation (para report)

- Allowlist de hosts/schemes; negar IP privado + link-local + metadata
- Nao seguir redirect para fora da allowlist (ou revalidar destino pos-redirect)
- Bloquear schemes perigosos (`file`, `gopher`, `dict`)
- Cloud: IMDSv2 + hop limit; exigir header metadata onde aplicavel
- Rede: egress default-deny para ranges sensiveis

## Fontes (lidas nesta deep session)

- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/ssrf/blind
- Labs: basic localhost, backend system, blacklist filter, open-redirection bypass
- https://medium.com/@vickieli/bypassing-ssrf-protection-e111ae70727b
- `hacktricks/.../ssrf-server-side-request-forgery/{README,url-format-bypass,cloud-ssrf}.md`
- `PayloadsAllTheThings/Server Side Request Forgery/{README,SSRF-Cloud-Instances}.md`
- WSTG-INPV-19
- `API-Security/editions/2023/en/0xa7-server-side-request-forgery.md`
- Bugcrowd University SSRF PDF → `_raw/bugcrowd_univ_ssrf_extract.txt`
- VRT SSRF variants (JSON local)

## Proxima deep sugerida

**Auth/JWT/OAuth** (`web-vulns/auth-session.md`) ou **Race** — mesma barra: labs + PDF/univ + nota com log.
