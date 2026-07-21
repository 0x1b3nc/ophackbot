# Auth, sessao, JWT, OAuth, reset — DEEP STUDY

Status: **deep study 2026-07-12**.  
Nivel tipico: **1–2**. Brute de secret HMAC / token curto = **3** so com policy.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger JWT (pagina principal, sessao anterior) | header/payload/sig; JWS vs JWE; impacto ATO |
| Lab: unverified signature | Trocar `sub`→`administrator` sem re-assinar → admin |
| Lab: flawed sig / alg none | `alg=none` + remover signature (deixar trailing `.`) |
| Lab: jwk header injection | Gerar RSA, Attack→Embedded JWK, `sub=administrator` |
| PortSwigger algorithm confusion | RS256→HS256 com public key como HMAC secret; JWKS; sig2n se chave nao publica |
| PortSwigger OAuth 2.0 (pagina completa) | code vs implicit; client_id/redirect_uri/response_type; well-known; state CSRF; redirect_uri steal code; implicit POST sem binding token↔user; scope upgrade; proxy page / open redirect |
| HackTricks JWT | jwt_tool `-M at`; workflow; none; HS brute; kid; jku; JWE+PlainJWT edge case |
| HackTricks OAuth→ATO | redirect_uri exact match RFC; substring/homograph/@/#; path em dominio allowlisted; state |
| PAT JSON Web Token | CVEs none, key confusion, key injection, kid, jku |
| WSTG OAuth AS | redirect_uri tamper; code injection/replay cross client_id |
| WSTG Session Fixation | Cookie pre-login deve mudar pos-auth |
| OAuth2 Cheat Sheet | PKCE; implicit deprecated; PoP/DPoP; state/nonce |
| VRT | Auth bypass **P1**; OAuth ATO **P2**; session fixation remote **P3**; JWT lifetime / weak hash muitas vezes **P5** sozinhos; OAuth insecure redirect / broken state = triage case-by-case |

## Modelo mental

| Camada | Pergunta |
|--------|----------|
| Autenticacao | Provo quem sou? (senha, OAuth, magic link) |
| Sessao / token | O que me identifica nas proximas requests? (cookie, JWT) |
| Autorizacao | Com esse token, o que posso fazer? (liga com BAC) |

JWT sozinho nao e authz: claims `role`/`sub` sem verificacao de assinatura = ATO.

## JWT — ataques na pratica

### Checklist rapido (HackTricks + labs)

1. Isolar qual cookie/header e o gate (remover um a um).
2. Decode: `alg`, `kid`, `jku`/`jwk`, `exp`, claims (`sub`,`role`,`admin`).
3. Flip bytes da signature → se ainda aceita, **unverified** (lab 1).
4. `alg=none` + signature vazia com trailing dot (lab 2).
5. Embutir `jwk` / apontar `jku` pra JWKS atacante (lab 3 / CVE key injection).
6. Se RS256 + JWKS publico: algorithm confusion → assinar HS256 com PEM da pubkey (PortSwigger).
7. HS256 fraco: `jwt_tool -C` / hashcat mode 16500 (**nivel 3** se wordlist grande).
8. `kid` path traversal / SQL se kid monta path ou query da chave (PAT).

### Ferramentas

- Burp **JWT Editor**
- `jwt_tool.py -M at` (All Tests)
- jwt.io so pra decode (nao confiar em “verified” sem a chave do server)

## OAuth — mapa de hunting

### Recon

- Login “with Google/X/…”, proxy: `/authorization?client_id=&redirect_uri=&response_type=&scope=&state=`
- `GET /.well-known/oauth-authorization-server` e `/.well-known/openid-configuration`

### Bugs de alto valor (PortSwigger + HackTricks)

1. **`redirect_uri` frouxo** → code/token vai pro atacante → ATO (VRT OAuth ATO **P2**).
   - Bypass: path extra, `@`, `#`, duplicate param, `localhost.evil`, traversal `/callback/../xss`, open redirect no host allowlisted.
2. **`state` ausente/previsivel** → CSRF de linkagem de conta / login CSRF.
3. **Implicit grant** + server confia no POST `{user, access_token}` sem validar token ↔ user → impersonation.
4. **Code replay / code de outro client_id** (WSTG).
5. **Scope upgrade** no token endpoint vs o que o user aprovou.
6. Implicit deprecated (RFC 9700 / cheat sheet): preferir code+**PKCE**.

## Sessao classica

- **Fixation** (WSTG-SESS-03): ID pre-login = pos-login → atacante fixa cookie.
- Logout/password change deve invalidar server-side (VRT Failure to Invalidate).
- Cookie Secure/HttpOnly/__Host-; sem token em URL.

## Reset / magic link (guia + TBHM)

- Token curto/previsivel; sem expiry; reuse apos uso; binding fraco email↔token.
- Priorizar: IDOR em change-password/email (liga com deep IDOR).

## Nivel de agressividade

| Acao | Nivel |
|------|-------|
| Decode JWT, 1 claim flip, OAuth param tamper | 1–2 |
| jwt_tool All Tests puntual | 2 |
| hashcat secret HMAC / brute reset token | 3 + policy |

## Aplicacao em hunting

- Cookies de SSO e sessao devem ser tratados como bearer tokens.
- JWT curto sozinho raramente tem impacto; impacto aparece quando authz falha
  com token valido.
- Qualquer login social/SSO/OAuth em alvo novo: mapear `redirect_uri`, `state`,
  `nonce`, PKCE e binding de identidade no primeiro dia.

## PoC minimo (JWT)

1. Login conta low-priv; capturar JWT.
2. Mutacao minima (`sub`/`role`) + ataque de verificacao (none / jwk / confusion).
3. Hit endpoint admin/self; controle = JWT original falha, forjado passa.

## PoC minimo (OAuth)

1. Capturar authorize URL.
2. Trocar `redirect_uri` pra OAST/evil (e variantes de bypass).
3. Se 302 pro evil com `code=` → roubo de code (nao precisa client_secret se client completa o exchange no callback legitimo — ver PortSwigger).

## Fontes

- https://portswigger.net/web-security/jwt (+ labs unverified, none, jwk; algorithm-confusion page)
- https://portswigger.net/web-security/oauth
- `hacktricks/.../hacking-jwt-json-web-tokens.md`
- `hacktricks/.../oauth-to-account-takeover.md`
- `PayloadsAllTheThings/JSON Web Token/README.md`
- WSTG OAuth AS + Session Fixation
- `CheatSheetSeries/cheatsheets/OAuth2_Cheat_Sheet.md`
- VRT: Broken Authentication… + Server Security Misconfiguration/OAuth Misconfiguration

## Proxima deep sugerida

**Race conditions** ou **GraphQL**.
