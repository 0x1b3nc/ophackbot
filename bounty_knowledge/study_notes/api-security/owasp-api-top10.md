# OWASP API Security Top 10 (2023)

Lido: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

| # | Risco | Hunting tipico neste workspace |
|---|--------|--------------------------------|
| API1 | BOLA | Contas A/B, troca de object id |
| API2 | Broken auth | JWT/OAuth/sessao |
| API3 | Property-level (mass assign + excess data) | Campos extras no JSON; response oversharing |
| API4 | Resource consumption | Rate/DoS-adjacent = nivel 3 + policy |
| API5 | BFLA | Endpoint admin com user comum |
| API6 | Sensitive business flows | Automacao abusiva de fluxo (compra, comment) |
| API7 | SSRF | URL fetch server-side |
| API8 | Misconfig | CORS, headers, stack defaults |
| API9 | Improper inventory | Versoes velhas de API, debug |
| API10 | Unsafe consumption | Confiar em API terceira |

Prioridade operacional: API1/API3/API5 primeiro em qualquer API nova.

## Nivel default

Testes A/B authz: **2**. Inventory passivo de endpoints: **0-1**.

## Fontes

- OWASP pagina acima
- `bounty_knowledge/API-Security/`
