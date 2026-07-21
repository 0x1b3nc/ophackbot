# GraphQL (+ smuggling / cache) — DEEP STUDY

Status: **GraphQL = DEEP 2026-07-12**. Smuggling/cache = **DEEP separado** em [smuggling-cache.md](smuggling-cache.md) (2026-07-12).  
Nivel tipico GraphQL: introspection/IDOR **1–2**; alias brute **2–3**; nested DoS **3 / OOS** na maior parte dos programas.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger GraphQL (pagina completa) | Universal query; paths; GET vs POST JSON; IDOR via args; introspection; newline bypass `__schema`; suggestions/Clairvoyance; aliases vs rate limit; CSRF se GET/urlencoded |
| Lab: finding hidden endpoint | `/api?query=` + newline apos `__schema` → delete carlos via mutation |
| Lab: reading private posts | ID sequencial missing + campo `postPassword` na introspeccao |
| Lab: brute force protection bypass | Aliases `bruteforceN:login(...)` numa mutation → rate limit HTTP nao conta ops |
| Lab: CSRF via GraphQL | `x-www-form-urlencoded` + Generate CSRF PoC → change email |
| HackTricks graphql.md | Paths; fingerprint graphw00f; batch Wallarm; CSRF GET/urlencoded/multipart; authz; alias/array/directive DoS; InQL/Threat Matrix |
| PAT GraphQL Injection | Tools; batch JSON list + alias; SQLi/NoSQLi em args; SecLists `graphql.txt` |
| WSTG-APIT-99 | Authz por resolver; batch IDOR/token; depth DoS; GraphQL como proxy sem re-authz |
| OWASP GraphQL Cheat Sheet | Depth/amount/cost; so JSON POST; introspection off; input validation |
| Guia study 4.7 | Introspection sozinha info/P4; smuggling session = P1 |
| VRT | GraphQL Introspection Enabled = **P5**; impacto real via BAC/IDOR |

## Modelo mental GraphQL

Um endpoint, muitas operacoes. Authn/authz **nao vem de graca** — cada resolver deve checar.

| Vetor | Pergunta |
|-------|----------|
| Discovery | Onde esta `/graphql`? Aceita GET/urlencoded? |
| Schema | Introspection? Suggestion leak? Wordlist/InQL? |
| Authz | `user(id:)` / mutation de outro sujeito? Campo privado no tipo? |
| Amplificacao | Aliases / JSON batch passam rate limit? |
| CSRF | Browser consegue forjar mutation? |
| Abuse | Depth/alias/directive → DoS (policy!) |

## Hunting checklist

### 1. Achar endpoint

Universal: `query{__typename}` → `{"data":{"__typename":"..."}}`.

Paths: `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphiql`, + `/v1`; wordlist `/usr/share/seclists/Discovery/Web-Content/graphql.txt`.

Metodos: POST `application/json` (seguro vs CSRF); tambem GET `?query=` e POST `x-www-form-urlencoded`.

Em APIs GraphQL persistidas (`/graphql/<docId>/<OperationName>`), o schema publico
nem sempre e o jogo; muitas vezes o valor esta nas operacoes capturadas no fluxo
real e nas mutations esquecidas.

### 2. Schema

Probe: `{"query":"{__schema{queryType{name}}}"}`.

Bypass regex fraca: newline/espaco/virgula apos `__schema` (lab hidden endpoint). Tentar GET se POST bloqueia.

Suggestions Apollo → Clairvoyance / InQL bruteforcer.

Campos `includeDeprecated: true` — senhas/flags escondidas (lab private posts).

### 3. Authz / IDOR (impacto real)

- Trocar IDs em args (`id`, `userId`, conversation key).
- Pedir campos sensiveis no tipo mesmo se a UI nao pede (`postPassword`, email, tokens).
- Mutations admin/delete com conta low-priv (lab delete carlos).
- WSTG: GraphQL traduz pra REST antigo sem re-checar authz do caller.

### Regra fixa nova: GraphQL = comecar pelas mutations

Nao cair na armadilha de ficar so em:
- introspection
- query read-only
- field exposure

Prioridade operacional:
- ir primeiro nas `mutations` que mudam estado;
- testar cadeia `BOLA + BFLA` dentro da mesma mutation.

Matriz minima:
1. trocar `id`/`object key`
2. trocar sessao ou role
3. trocar ambos
4. se a mutation aceitar lista (`ids`, `items`, `nodes`, `input[]`), enviar IDs mistos no mesmo request e inverter a ordem:
   - primeiro ID autorizado, segundo ID de outro tenant
   - primeiro ID de outro tenant, segundo ID autorizado

Falha procurada: a API autoriza so o primeiro objeto do array e executa a mutation no lote inteiro. Isso costuma esconder cross-tenant write/data exposure atras de uma mutation que parece segura no teste de ID unico.

Perguntas que devem virar reflexo:
- writer consegue alterar objeto de owner/admin?
- member sem role correta consegue disparar acao de admin?
- read-only member consegue mutar por mutation esquecida?
- query de leitura esta protegida, mas a mutation equivalente ficou aberta?

Triager espera muito mais `introspection enabled` do que `authz chain on mutation`.
Essa assimetria e uma vantagem real.

Em mensageria, arquivos, upload e membership, priorizar BOLA/BFLA em IDs de
conversa, recurso e usuario, nao introspection isolada.

### 4. Aliases e batch (rate limit)

Aliases (PortSwigger lab login):

```graphql
mutation {
  a0: login(input:{username:"carlos", password:"123456"}) { success token }
  a1: login(input:{username:"carlos", password:"password"}) { success token }
}
```

JSON array batch (PAT/Wallarm): `[{ "query": "..." }, { "query": "..." }]`.

Rate limit por **HTTP request** ≠ por operacao. Nivel 2–3; evitar brute massivo
sem autorizacao explicita.

### 5. CSRF

Se aceita GET ou `x-www-form-urlencoded` (ou multipart sem preflight) **sem** token CSRF → change-email / transfer forgery (lab CSRF). Preferencia de defesa: so JSON POST + validar Content-Type + token.

### 6. DoS GraphQL (quase sempre OOS)

Depth nesting, alias overload, array batch gigante, directive overload, field duplication, `@defer` fan-out. Em bounty: **nao** sem policy DoS; documentar so se programa pedir.

## PoC minimo (GraphQL IDOR)

1. Capturar query legitima no Burp.
2. Introspection ou campo extra no mesmo tipo.
3. `id` da conta B / recurso oculto; conta A autenticada.
4. Controle: sem auth ou id proprio ≠ dado alheio.
5. Reportar como BAC/IDOR (nao “introspection P5”).

## Ferramentas (VM)

- Burp GraphQL tab / InQL (se instalado); SecLists graphql.txt.
- `which`: graphql-cop / graphw00f / clairvoyance **ausentes** nesta VM — instalar leve so se preciso; nao Docker.
- Nuclei: `http/misconfiguration/graphql/` (alias-batching, introspection, etc.) com `-c` baixo.

## Nivel

| Acao | Nivel |
|------|-------|
| `__typename`, introspection pontual, 1 ID flip | 1–2 |
| Alias batch login / 2FA (dezenas) | 2–3 + policy |
| Depth/alias DoS | 3 / OOS |

## VRT / report

- Introspection enabled → VRT **P5** sozinha.
- IDOR/mutation authz → BAC P1–P4 conforme dado.
- Alias bypass que viabiliza ATO → impacto do ATO, nao “misconfig GraphQL”.

## Aplicacao em hunting

- Se operacoes reais ja foram capturadas no Burp/HAR, priorizar replay A/B em
  mutations, batch inputs e objetos de outro tenant.
- Nao gastar a sessao inteira em `__schema` quando a superficie real esta em
  write paths autenticados.
- Evitar race/flood sem hipotese de estado compartilhado e autorizacao clara.

---

## Request smuggling / cache

**DEEP completo:** [smuggling-cache.md](smuggling-cache.md) (CL.TE/TE.CL, timing, Param Miner, poison vs deception, Gotta Cache Em All).

## Fontes (GraphQL)

- https://portswigger.net/web-security/graphql (+ labs endpoint, private posts, aliases, CSRF, field exposure)
- `hacktricks/.../graphql.md`
- `PayloadsAllTheThings/GraphQL Injection/README.md`
- `wstg/.../99-Testing_GraphQL.md`
- `CheatSheetSeries/cheatsheets/GraphQL_Cheat_Sheet.md`
- `/usr/share/seclists/Discovery/Web-Content/graphql.txt`
- VRT: Sensitive Data Exposure / GraphQL Introspection Enabled P5
