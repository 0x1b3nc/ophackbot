# HTTP request smuggling + web cache poisoning/deception — DEEP STUDY

Status: **deep study 2026-07-12** (fecha a trilha do guia §4.7 junto com GraphQL).  
Nivel tipico: **2** com cache buster + cuidado extremo. Pode afetar **outros users** → releia policy; X SCOPE proibe DoS/cache avail abuse.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger Request smuggling (pagina completa) | CL.TE / TE.CL / TE.TE obfuscation; H2 end-to-end imune; H2→H1 downgrade risco; prevent normalize/reject |
| PortSwigger Finding smuggling | Timing delay detect; differential responses; conexoes **diferentes**; TE.CL timing pode afetar outros se CL.TE |
| PortSwigger Web cache poisoning | Cache key vs unkeyed; Param Miner; elicit harm + get cached; Age/Vary leaks |
| PortSwigger Exploiting design flaws | X-Forwarded-Host→XSS/JS import; cookie unkeyed; multi-header redirect; DOM via JSON; chain |
| HackTricks response smuggling / desync | Response queue; HEAD/TRACE gadgets; confirmar server-side vs client pipelining |
| HackTricks cache deception README + URL discrepancies | Poison vs deception; Gotta Cache Em All delimiters/static ext; Cloudflare ext list |
| WSTG-INPV-16 | CL/TE; H2 downgrade; H2C |
| Guia study 4.7 | Smuggling session = P1; cache+XSS = P1–P2 |
| VRT | HTTP Request Smuggling / Cache Poisoning / Cache Deception = containers (impacto define P) |
| Nuclei locais | `http/vulnerabilities/smuggling/`, `cache-poisoning*.yaml` |

## Parte A — Request smuggling

### Modelo mental

Front e back discordam **onde termina** o request na mesma conexao TCP → bytes “sobrando” viram prefixo do request da **proxima** vitima (ou do teu probe).

```
[Attack request ambiguo] ──front──▶ [encaminha N bytes]
                                    back ve fim cedo
                                    └── SMUGGLED vira inicio do proximo
```

| Variante | Front usa | Back usa |
|----------|-----------|----------|
| **CL.TE** | Content-Length | Transfer-Encoding chunked |
| **TE.CL** | TE chunked | Content-Length |
| **TE.TE** | ambos TE; um ignora TE **ofuscado** | |

HTTP/2 **ponta a ponta** = imune (length unico). Front H2 + back H1 (downgrade) = superficie avancada (PS “sequel is always worse”).

### Detect (ordem segura)

1. **CL.TE timing** primeiro (menos risco de atrapalhar fila alheia):

```http
POST / HTTP/1.1
Host: alvo
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Delay no back esperando chunk = pista.

2. So se negativo: **TE.CL timing** (pode perturbar se for CL.TE vulneravel).

3. **Confirmar** com attack + normal em **sockets diferentes**, mesmo path/params (mesmo backend), race com trafego real.

Burp: desligar “Update Content-Length” em TE.CL; forcar HTTP/1 no Repeater se site anuncia H2.

### Ofuscacao TE (TE.TE)

Exemplos PS: `Transfer-Encoding: xchunked`, espaco antes do nome, tab apos `:`, TE duplicado, newline no meio do header name…

### Impactos classicos

- Prefixar request da vitima → path/host/header (bypass front ACL, open redirect interno).
- Capturar request da vitima (Cookie/Authorization) se refletido/armazenado.
- Envenenar cache via smuggled response (liga Parte B).
- Response queue desync (HT): vitima recebe HTML/XSS teu; atacante recebe Set-Cookie dela.

### Confirmacao anti-FP (HT)

Se so “funciona” com reuse/pipelining no **teu** cliente → pode ser artifact. Retestar sem reuse; H2 downgrade com nested H1 na resposta = sinal forte.

### Nivel / safety

| Acao | Nivel |
|------|-------|
| Timing pontual 1–2 reqs | 2 |
| Differential em lab / staging | 2 |
| Persistir smuggling em prod busy | 2–3; alto risco collateral |
| DoS via desync | OOS |

Em **X**: SCOPE diz DoS/cache avail proibido — smuggling live so se hipotese clara e burst minimo; preferir labs PS antes.

---

## Parte B — Cache poisoning vs deception

### Diferenca (HT)

| | Poisoning | Deception |
|--|-----------|-----------|
| Quem sofre | Outros users recebem **payload** teu | Atacante le **dado sensivel** da vitima no cache |
| Mecanica | Unkeyed input → resposta maliciosa cacheada | Enganar cache a guardar pagina dinamica “como estatica” |

### Poisoning — 3 passos (PS)

1. **Unkeyed inputs** — Param Miner “Guess headers”; `X-Forwarded-Host` / `X-Forwarded-Scheme` / `X-Original-URL` comuns. **Sempre** cache buster unico (`?cb=uuid`) pra nao envenenar users reais no teste.
2. **Harmful response** — reflection XSS, import JS de evil host, redirect Location, JSON→DOM sink.
3. **Get cached** — observar `Age`, `X-Cache`, `CF-Cache-Status`, `Via`; `Cache-Control: public`; path/ext/status que CDN cacheia.

Exemplo classico: `X-Forwarded-Host: evil"><script>` refletido em meta/script URL + resposta `public` → todos com mesma cache key levam XSS.

### Deception / URL discrepancies (“Gotta Cache Em All”)

Cache key ≠ path que o origin resolve:

- Delimiters: `;` (Spring), `.` (Rails format), `%00`, `%0a`…
- Encoding: cache nao decodifica `?` encoded, origin sim.
- Dot-segments: `/static/../home` cacheia como static, origin serve `/home`.
- Forcar “estatico”: `/account/..%2frobots.txt` ou `/home$image.png` (Cloudflare lista de ext).

Meta: pagina autenticada da vitima (com cookie) fica cacheada sob URL “estatica” → atacante GET sem cookie e le PII.

### Headers uteis

`Age`, `Cache-Control`, `Vary`, `X-Cache` / `CF-Cache-Status` / `X-Varnish`.

### Nivel

| Acao | Nivel |
|------|-------|
| Param Miner + cache buster so pra ti | 2 |
| Poison path popular sem buster | **proibido** (afeta users) |
| Deception em path proprio autenticado | 2 |

---

## Encadeamento smuggling ↔ cache

Smuggle um request que muda Host/path/header unkeyed → resposta toxica cacheada → distribuicao em massa sem vitima clicar no teu link. Reportar como impacto composto.

## VRT / report

- Smuggling com session hijack / request capture → tipicamente **P1**.
- Cache poison + XSS stored-like → **P1–P2**.
- Deception PII → **P1–P2** conforme dado.
- So “timing delay” sem impacto → Informal / nao reportar.

PoC: timing ou differential + um impacto (404 forçado / reflection / Age>0 com payload). Nunca deixar poison ativo.

## Ligacao hunting

- Superficies com CDN/Akamai/Cloudflare + app dinamica = cache.
- Multi-hop proxy (comum em APIs) = smuggling candidato.
- CDNs e multi-hop proxies exigem cache buster, controles negativos e zero
  stress sem policy explicita.

## Fontes

- https://portswigger.net/web-security/request-smuggling (+ finding, exploiting, advanced, browser-powered)
- https://portswigger.net/web-security/web-cache-poisoning (+ design flaws, implementation)
- https://portswigger.net/research/gotta-cache-em-all
- `hacktricks/.../http-response-smuggling-desync.md`, `cache-deception/`
- WSTG-INPV-16
- Guia §4.7; VRT containers Smuggling / Cache Poisoning / Deception
- Nuclei: `vulnerabilities/smuggling/`, `cache-poisoning*`

## Sessao de estudo

Com esta nota + GraphQL DEEP, o bloco API-specific do guia (§4.7) fecha. Trilha study do guia (vulns + recon) = **completa** nesta base.
