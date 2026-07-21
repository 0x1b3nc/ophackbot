# Race conditions e logica — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel tipico: **3** (paralelo = volume). Em bug bounty, race live so com
justificativa, alvo proprio, volume minimo e policy permitindo esse nivel.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger Race conditions (pagina completa) | Race window / sub-estado; limit overrun TOCTOU; H1 last-byte vs H2 single-packet; metodologia predict→probe→prove; multi-endpoint; single-endpoint; session locking PHP; partial construction; time-sensitive tokens |
| Lab: limit overrun | Coupon `POST /cart/coupon` 20× parallel → desconto repetido → jacket barato |
| Whitepaper “Smashing the state machine” (via PS + HT) | Colisao em mesmo record; MFA sub-state; email verify race; GitLab-style dual email |
| HackTricks race-condition.md | Sync H2/H3; connection warming; rate-limit delay trick; Turbo Intruder gates; WS race; OAuth code/RT race; first-sequence-sync 65k |
| PAT Race Condition | Tools (Turbo, h2spacex, Raceocat); limit-overrun + rate-limit bypass; labs list |
| Guia study 4.5 | Financeiro P1–P2; duplicacao sem valor P4–P5 |
| VRT | No `Server Security Misconfiguration/Race Condition` (sem filhos/priority fixa) → severidade pelo **impacto** (IDOR/finance/auth), nao pela label “race” |

## Modelo mental

App processa requests **ao mesmo tempo** sem lock/atomicidade → duas threads leem o mesmo estado “ainda livre” e ambas escrevem sucesso.

```
check(limit OK) ──race window──▶ act() ──▶ mark_used()
         ▲                              │
         └── segundo request ainda ve “OK”
```

| Classe | Ideia | Exemplo |
|--------|-------|---------|
| Limit overrun | Ultrapassar teto 1× | Cupom, gift card, like, withdraw |
| Hidden multi-step | Sub-estado dentro de **1** request | Session criada antes de `enforce_mfa` |
| Multi-endpoint | Dois endpoints no mesmo record | Pay + add-to-cart |
| Single-endpoint | Dois valores paralelos no mesmo handler | Reset: session fica `victim` + token do attacker |
| Partial construction | Objeto meio-criado | User existe, `api_key` ainda null → `api-key[]=` |
| Time-sensitive | Timing sem “race de estado” | Token = timestamp → dois resets = mesmo token |

## Metodologia (PortSwigger)

1. **Predict** — endpoint critico? Colisao no **mesmo** record/ID/sessao?
2. **Benchmark** — grupo em **sequence** (separate connections): comportamento normal.
3. **Probe** — mesmo grupo **in parallel** (Repeater / Turbo / custom action). Qualquer desvio conta (status, body, email, UI).
4. **Prove** — minimizar requests; reproduzir; documentar impacto.

### Timing (por que “20 curls” falha)

- **HTTP/2 single-packet:** ~20–30 streams, ultimo frame no mesmo TCP packet → jitter de rede ≈ 0 (Burp 2023.9+ / Turbo `Engine.BURP2` + `gate`/`openGate`).
- **HTTP/1.1 last-byte sync:** manda quase tudo, segura 1 byte, flush junto.
- **HTTP/3:** last-frame sync em QUIC (H3SpaceX) — nao e Nagle/TCP.
- **PHP session lock:** requests da mesma sessao serializam → mascara RC; testar com **sessoes diferentes** se fizer sentido.
- **Warming:** GET inocente no inicio do grupo / ping H2 antes do gate.
- **Align windows:** flood dummy pra forcar delay server-side se um endpoint e mais lento.
- **First-sequence-sync (2024):** estende single-packet alem de ~1500 B via fragmentacao IP → ate dezenas de milhares de reqs; servers limitam `MAX_CONCURRENT_STREAMS` (Apache ~100).

## Onde caçar (superficie)

Cupom/gift, saldo/transfer, convite “N usos”, rate-limit login/2FA/CAPTCHA,
password/email reset+verify, checkout/pay, follow/like/vote, OAuth
`authorization_code` / refresh token reuse, WebSocket handlers com estado.

## PoC minimo (limit overrun)

1. Acao single-use com impacto (cupom, redeem).
2. Benchmark: 2× sequence → 1 OK + N “already used”.
3. Parallel 10–20 (H2 se der).
4. Contar sucessos > 1; evidenciar estado (saldo/pedido).
5. Reverter se der (cancelar pedidos).

Turbo Intruder esqueleto:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='1')
    engine.openGate('1')
```

## Nivel de agressividade

| Acao | Nivel |
|------|-------|
| 2–5 parallel pontual em endpoint proprio | 2 (borda) |
| 20–50 single-packet em fluxo de valor | **3** + policy |
| 1k+ / first-sequence-sync / DoS-adjacent | **3** + releitura policy; evitar sem autorizacao explicita |

## Aplicacao em hunting

- Race so vale quando houver hipotese de impacto claro e burst curto.
- Candidatos: redeem/limites de convite, reset/verify, OAuth code reuse,
  WebSocket handlers e fluxos financeiros.
- Nao misturar “mandei 50 GETs” com progresso: precisa hipotese de colisao no
  mesmo record.

## VRT / report

VRT nao fixa P# em “Race Condition”. Mapear impacto:

- Dinheiro / saldo / compra gratis → P1–P2 (Application Logic / BAC conforme encaixe).
- Bypass 2FA / ATO via race → P1–P2.
- Duplicar like/voto cosmetico → P4–P5.
- Rate-limit bypass sozinho → muitas vezes P4–P5 a menos que habilite brute sensivel.

Report: timing method (single-packet), N requests, estados before/after, controle sequencial.

## Fontes

- https://portswigger.net/web-security/race-conditions (+ labs limit/multi/single/partial/time-sensitive/rate-limit)
- https://portswigger.net/research/smashing-the-state-machine
- `hacktricks/.../race-condition.md`
- `PayloadsAllTheThings/Race Condition/README.md`
- Guia `BUGBOUNTY_STUDY_GUIDE.md` §4.5
- VRT: Server Security Misconfiguration → Race Condition (container)

## Proxima deep sugerida

Injection (SQLi/NoSQL/SSTI) ou client-side (DOM XSS / PP).
