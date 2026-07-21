# Client-side: DOM XSS, prototype pollution, postMessage — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel tipico: **0–1** analise de JS publico; **1–2** confirmacao no browser. Sem flood.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger DOM-based vulnerabilities | Source→sink taint; lista de sources; open redirect DOM exemplo; DOM clobbering ponteiro |
| PortSwigger DOM XSS | Test HTML sink vs JS sink; DOM Invader; `innerHTML` sem `<script>` (usar img/iframe+onerror); jQuery `attr`/`$()`; Angular `{{}}`; reflected/stored DOM XSS |
| PortSwigger web messages | `postMessage` → `eval(e.data)`; origin check fraco `indexOf`/`startsWith`/`endsWith` bypass |
| PortSwigger Prototype pollution | Source URL/JSON/message; sink+gadget; `transport_url` → script.src / data: XSS |
| HackTricks DOM XSS | Tabela sources/sinks ampla; tools eslint-no-unsanitized / domloggerpp |
| HackTricks client-side PP | ppfuzz/ppmap/PPScan; debugAccess; gadgets fetch/defineProperty/localStorage/GTM |
| HackTricks postMessage README | Envio iframe/popup; wildcard targetOrigin leak; `getEventListeners(window)`; posta / postMessage-tracker |
| PAT XSS Injection + Prototype Pollution | Payloads/gadgets refs; BlackFan gadgets |
| WSTG-INPV-22 Prototype Pollution | Merge recursivo; probe `__proto__` / `constructor.prototype`; client vs server |
| Guia study 4.8 | PP→XSS; DOM Invader; postMessage sem origin |
| VRT | XSS root **P3** (VRT flat neste JSON); PP sozinho sem impacto = baixo; PP→RCE server = P1 |
| BC Univ XSS PDF | Presente localmente; pdftotext nao instalado nesta sessao |

## Modelo mental

Tudo e **fluxo de taint no browser** (ou no Node, se PP server-side):

```
SOURCE (atacante controla) ──▶ codigo JS ──▶ SINK (efeito perigoso)
```

| Bug | Source tipico | Sink / gadget | Resultado |
|-----|---------------|---------------|-----------|
| DOM XSS | `location.*`, reflected string | `innerHTML`, `eval`, `document.write` | JS na origem da vitima |
| postMessage | `event.data` de origem maliciosa | mesmo sinks | XSS / acao sensivel |
| Prototype pollution | `__proto__` em URL/JSON/message | propriedade herdada lida sem filtro | XSS / bypass / RCE (Node) |

## DOM XSS

### Sources comuns (PS + HT)

`location` / `document.URL` / `document.referrer` / `document.cookie` / `window.name` / `localStorage` / `sessionStorage` / web messages / dados refletidos ou stored que o JS relê.

### Sinks XSS

`document.write`, `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `eval`/`Function`/`setTimeout(string)`, handlers `on*`, jQuery `html`/`append`/`$()`, `script.src`, etc.

**Nota `innerHTML`:** browsers modernos nao executam `<script>` injetado nem `svg onload` classico da mesma forma — preferir `<img src=x onerror=...>` / `<iframe>` / event handlers.

### Como testar (manual)

1. Colocar canario alfanumerico na source (`?q=Canary9x`).
2. DevTools → Elements search (nao “View Source” — perde DOM dinamico).
3. Ver contexto (attr quoted, HTML body, JS string) e quebrar conforme.
4. Sinks JS puros: Ctrl+Shift+F no source; breakpoint; seguir variavel ate o sink.

### Framework traps

- jQuery `$('#backLink').attr('href', returnUrl)` → `javascript:alert(1)`.
- jQuery `$()` + `location.hash` + `hashchange` → iframe muda hash sem click (lab classico; jQuery novo mitiga `#` prefix).
- AngularJS `ng-app` + `{{constructor.constructor('alert(1)')()}}` em contextos certos.

### Reflected / stored DOM XSS

Server ecoa dado numa string JS ou no DOM; **outro script** leva ao sink. Buscar `eval('...'+reflected)` ou `innerHTML = comment.author`.

### Ferramentas

Burp **DOM Invader** (browser Burp); `katana` + `rg` sinks no JS baixado; domloggerpp / eslint-plugin-no-unsanitized.

## postMessage

### Padrao vulneravel

```javascript
window.addEventListener('message', function(e) {
  // sem check de e.origin (ou check fraco)
  eval(e.data);           // ou innerHTML = e.data
});
```

Atacante: pagina maliciosa com `iframe`/`open` + `contentWindow.postMessage(payload, '*')`.

### Checks fracos (PS)

- `e.origin.indexOf('normal-website.com')` → `evil.com.normal-website.com.attacker.net` ou host que **contem** a substring.
- `startsWith` / `endsWith` semelhantes.

### targetOrigin bypass via IPv4 normalization

Fonte: CTBB / Mathias Karlsson, 2026-07-06 + WHATWG URL IPv4 parser/serializer.

Ideia: `postMessage(data, targetOrigin)` normaliza o `targetOrigin` com o URL parser do browser antes de comparar origem. Hosts numericos podem ser interpretados como IPv4 e serializados em dotted quad:

- `2130706433` -> `127.0.0.1`
- `127.1` -> `127.0.0.1`
- hex/octal/short IPv4 tambem entram nessa familia, dependendo do formato aceito pelo parser.

Padrao exploravel:

```javascript
const origin = new URLSearchParams(location.search).get('origin');
if (/^https?:\/\/[^.]+[.]target[.]com/.test(origin)) {
  otherWindow.postMessage(secret, origin);
}
```

Payload conceitual:

```text
http://2130706433/.target.com
```

O regex roda no texto cru e pode aceitar `2130706433/.target.com` como se fosse subdominio de `target.com`. O browser parseia o host como `2130706433`, normaliza para `127.0.0.1`, e `/.target.com` vira apenas path. Resultado: a mensagem pode ser enviada para `http://127.0.0.1`.

Checklist:

- Procurar `postMessage(..., userControlledOrigin)` e `targetOrigin` vindo de query/hash/config externa.
- Procurar regex/string checks antes do `postMessage`, principalmente `[^.]+[.]target[.]com`, `includes`, `startsWith`, `endsWith`.
- Testar variantes: `2130706433`, `127.1`, `0x7f000001`, octal/short forms, e path `/.target.com`.
- Diferenciar de SSRF: ja usamos formas alternativas de IP em contexto SSRF/allowlist, mas **ainda nao aplicamos exatamente esta cadeia em postMessage** nos programas recentes.

### Enumeration (HT)

- `getEventListeners(window)` no console.
- Elements → Event Listeners.
- Extensoes: posta, postMessage-tracker.
- `rg` por `addEventListener('message'` / `.on('message'`.

### Outro angulo

Pagina que **envia** segredo com `targetOrigin: '*'` e e iframavel → atacante troca location do frame e **rouba** a mensagem (Google VRP pattern no HT).

## Prototype pollution (client)

### Componentes (PS)

1. **Source** — URL `?__proto__[k]=v` / `#__proto__[k]=v` / `constructor[prototype][k]=v`; JSON `{"__proto__":{...}}` apos `JSON.parse`+merge; web message.
2. **Pollution** — merge/clone recursivo sem filtrar chaves.
3. **Gadget** — codigo que le propriedade **ausente** no objeto proprio e herda do prototype → sink (`script.src`, `innerHTML`, `fetch` options, etc.).

Confirmacao:

```javascript
// apos visitar URL de probe
({}).testpolluted  // deve ser o valor injetado
```

### Gadgets faceis de perder (HT)

- `fetch(url, {method:'POST'})` herda `body`/`credentials` poluidos.
- `Object.defineProperty` descriptor incompleto herda `value`.
- `localStorage.foo` (prototype) vs `getItem` (imune).
- Analytics/GTM/tag managers historicamente ricos em gadgets.

### Server-side PP (WSTG)

Mesma root cause em Node merge; impacto via gadget → DoS / auth bypass / **RCE**
(ex. Kibana). Deteccao black-box: poluir propriedade e observar mudanca de
comportamento (status, body, header). Em bug bounty web comum, client-side
costuma ser o primeiro caminho.

### Tools

DOM Invader gadget scan; ppmap/ppfuzz/PPScan; PAT BlackFan gadget lists. `which` antes de instalar.

## DOM clobbering (ponteiro)

Injetar HTML (`<a id=x>`) que sobrescreve globais que o JS assume como objetos — pode virar XSS se o site usa o global clobbered em sink. Ver pagina dedicada PS quando aparecer `id=` refletido + JS ingenuo.

## Nivel

| Acao | Nivel |
|------|-------|
| Ler JS / `rg` sinks / DOM Invader scan | 0–1 |
| Abrir URL propria com payload XSS/PP | 1–2 |
| Spam de vitimas reais / worm | OOS |

## VRT / report

- DOM XSS exploravel (self + prova em browser) → tipicamente **P2–P3** (VRT XSS P3 neste dump; H1/BC ajustam por impacto/sessao).
- postMessage → XSS ou mudanca de email/senha: severidade do impacto final.
- PP sem gadget = muitas vezes Informative / P5.
- PP + gadget XSS = XSS.
- PP server RCE = **P1**.

Report: URL/payload minimo, source→sink (trecho JS), screenshot/console, browser. Sem cookie de sessao no texto.

## Aplicacao em hunting

- SPAs pesadas: DOM XSS, postMessage entre frames e prototype pollution em libs
  de merge sao vetores reais.
- Baixar bundles JS do alvo → `rg`
  `innerHTML|dangerouslySetInnerHTML|postMessage|__proto__|document.write|eval(`.
- Preferir DOM Invader numa pagina autenticada de teste antes de fuzz cego.

## PoC minimo

**DOM XSS:** URL com payload → sink executa `alert(document.domain)` (ou `print`) na origem do alvo.

**postMessage:** HTML atacante local → iframe vitima → message → execucao na origem vitima.

**PP:** URL/JSON polui `Object.prototype.x` → gadget carrega script/data URL → XSS.

## Fontes

- https://portswigger.net/web-security/dom-based
- https://portswigger.net/web-security/cross-site-scripting/dom-based
- https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
- https://portswigger.net/web-security/prototype-pollution
- `hacktricks/.../dom-xss.md`, `client-side-prototype-pollution.md`, `postmessage-vulnerabilities/README.md`
- PAT XSS Injection + Prototype Pollution
- WSTG-INPV-01/02 (XSS) + 22 (PP)
- Guia `BUGBOUNTY_STUDY_GUIDE.md` §4.8

## Proxima deep sugerida

Recon (subdomain takeover + content discovery) ou HTTP smuggling/cache (ainda ponteiro na nota GraphQL).
