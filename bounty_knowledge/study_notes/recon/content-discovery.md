# Content discovery e fingerprint — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel: passivo **0**; enum/crawl **1**; ffuf/nuclei padrao **2**; alta concorrencia / dos tags **3** + policy.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| TBHM 01 Philosophy | Crowdsource = road less traveled; templates de report |
| TBHM 02 Discovery | ^scope; Google dorks; M&A; port scan full pra web obscure |
| TBHM 03 Mapping | Smart dirbrute (RAFT/SVN/Git Digger); 401→bruteforce sob path; tech fingerprint; OSINT bugs antigos |
| TOOLCHAIN.md | Pipeline PD local; rate nuclei VM |
| Guia study §5–7 | Pipeline subfinder→dnsx→httpx→nuclei; SecLists path; ffuf; -rl 10–30 |
| awesome-bugbounty-tools Content Discovery / Links / Parameters | katana, feroxbuster, kiterunner, gau, waybackurls, waymore, LinkFinder, arjun, ParamSpider, jsluice |
| reconFTW README + cfg | Orquestrador amplo; FUZZ/HTTPX rates; SUBTAKEOVER; robots wayback DEEP |
| Persona recon-advisor | OPSEC QUIET/MODERATE/LOUD; evidencias timestamped; least aggressive first |
| SecLists locais | `/usr/share/seclists` Discovery/Web-Content + DNS |
| which VM | subfinder, dnsx, httpx, katana, gau, waybackurls, ffuf, nuclei, amass, arjun, feroxbuster, gobuster — OK |

## Modelo mental (TBHM)

Bug bounty ≠ pentest de checklist. Objetivo: achar superficie **menos testada** e mapear caminhos ate authz/injection.

```
Escopo ──▶ assets (subs/IPs) ──▶ live HTTP ──▶ URLs/paths/params/JS
                                              │
                                              ▼
                                    hipotese de impacto (nao inventario eterno)
```

## Pipeline padrao deste workspace

```bash
# Nivel 0–1 — passivo + live
subfinder -d alvo.com -silent | tee subs.txt
cat subs.txt | dnsx -silent | httpx -silent -title -tech-detect -status-code -o live.json

# Historico URLs (nivel 0)
echo alvo.com | gau --subs | tee gau.txt
echo alvo.com | waybackurls | tee wb.txt
# unir + filtrar escopo

# Crawl raso (nivel 1)
katana -list live.txt -d 2 -silent -o katana.txt

# JS endpoints (nivel 1)
# katana -jc  ou getJS / jsluice / LinkFinder nos bundles

# Content discovery (nivel 2) — rate consciente
ffuf -u https://alvo.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -fc 404 -t 20 -rate 20 -o ffuf_common.json

# Params
arjun -u 'https://alvo.com/api/endpoint' -oT arjun.txt

# Nuclei seletivo (NAO default 150 rps)
nuclei -l live.txt -tags exposure,misconfig,cve -severity critical,high,medium \
  -c 5 -rl 10 -o nuclei.txt
```

**reconFTW** quando o dominio merece pass amplo (um alvo, nao 50 curls). Docker do reconFTW = fora nesta VM se for stack pesada; preferir modo local ja no repo.

**Ajuste vs reconFTW defaults:** cfg usa `HTTPX_RATELIMIT=150` / ffuf threads altos — na nossa postura VM/policy, baixar pra 10–30 rps e `-c 5–10` no nuclei.

## Camadas de discovery

### 1. Asset discovery (TBHM Discovery)

- Wildcard `*.company.com` = amigo.
- CT logs, subfinder, amass passive, GitHub/GitLab subdomain tools.
- M&A / trademark / privacy policy → dominios irmaos (checar escopo!).
- Port scan leve (`naabu`) em hosts novos — Jenkins/RDP historicos (TBHM Facebook/IIS).
- Mobile / API hosts / staging / redesign.

Wordlists DNS: `/usr/share/seclists/Discovery/DNS/` (`dns-Jhaddix.txt`, top1m 5k–20k primeiro).

### 2. URL / path discovery

| Fonte | Noise | Uso |
|-------|-------|-----|
| gau / waybackurls / waymore | 0 | Historico, params antigos |
| robots.txt / sitemap | 0–1 | Paths oficiais |
| katana crawl | 1 | Links vivos + JS |
| ffuf / feroxbuster / gobuster | 2 | Dirs/files |
| kiterunner | 2 | APIs modernas (wordlists Assetnote) |

TBHM trick: achar **401/403** em `/controlpanel/` → **ffuf sob esse prefixo** (ACL misconfig).

Wordlists Web: `common.txt`, `raft-*`, `DirBuster-*`, `api/`, `graphql.txt` em SecLists — nao clonar SecLists de novo.

### 3. Parameter / API discovery

- arjun (na VM), ParamSpider (arquivos), Burp Param Miner (cache poisoning / hidden).
- Diff de responses: status, length, reflection.
- GraphQL: ver nota DEEP GraphQL (`query{__typename}`).

### 4. JS mining

katana `-jc`, getJS, **jsluice**, LinkFinder, xnLinkFinder → endpoints, secrets patterns, sourcemaps.  
Liga com client-side DEEP (sinks) e api-security.

### 5. Fingerprint

httpx `-tech-detect`, Wappalyzer/BuiltWith, retire.js → CVE known.  
Nuclei `technologies/` com rate baixo. WPScan/CMSmap so se CMS confirmado e in-scope.

## Smart fuzz (TBHM + pratica)

1. Começar wordlist **pequena** (`common.txt` / raft-small).
2. Filtrar baseline (404 size, WAF soft-404) — `-fs`/`-fw` no ffuf.
3. Recursao so em dirs interessantes (`-recursion` controlado; reconFTW DEEP depth 2).
4. Status nao-200: 301, 401, 403, 500 = pistas.
5. VHost fuzz se multi-tenant (`ffuf -H Host: FUZZ.alvo.com`).

## O que NAO e progresso

- Lista de 10k paths 404 sem hipotese.
- nuclei full template dump no flagship.
- Inventariar sem pivot pra authz/IDOR/injection na superficie nova.

Apos 1–2 hosts “interessantes”: **parar recon amplo** e caçar (bizlogic, GraphQL, JS sinks).

## Nivel de agressividade

| Acao | Nivel |
|------|-------|
| CT, gau, wayback, crt.sh | 0 |
| subfinder, httpx, katana -d2 | 1 |
| ffuf common + nuclei exposure/misconfig | 2 |
| ffuf big + recursion profunda + nuclei -itags dos/fuzz | 3 + policy |
| Port scan -p- em toda a org | 2–3; checar DoS/policy |

## Artefatos (persona recon-advisor)

Salvar em `targets/<slug>/recon/` ou `recon_<alvo>/`:

`{tool}_{alvo}_{YYYYMMDD_HHMMSS}.txt`

Nunca `| bash` em output do alvo.

## Ligacao com takeover

Toda lista `live.txt` / CNAME de `dnsx` → feed da nota **subdomain-takeover** (nuclei takeovers) na mesma sessao de recon.

## Ligacao hunting X / programas

- X: escopo enorme — discovery seletivo (chat, grok, money, communities), nao “ffuf x.com inteiro”.
- Bugcrowd/H1 novo: reconFTW ou PD pipeline → httpx live → JS/API → candidatos → Burp/HexStrike.

## Fontes

- `tbhm/01_Philosophy.md`, `02_Discovery.md`, `03_Mapping.md`
- `bounty_knowledge/TOOLCHAIN.md`
- `BUGBOUNTY_STUDY_GUIDE.md` §5–7
- `awesome-bugbounty-tools` Content Discovery / Links / Parameters
- `reconftw/` (README + cfg rates)
- `/usr/share/seclists`
- Persona `recon-advisor.md`

## Proxima deep sugerida

HTTP request smuggling + cache poisoning (ainda ponteiro na nota GraphQL), ou fechar estudo e caçar.
