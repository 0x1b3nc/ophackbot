# Lições reutilizáveis — Mobile / API / Auth

Fonte: síntese operacional de padrões recorrentes em APK, CIAM,
ForgeRock/ADFS, APIM e portais employee.  
**Obrigatório reler** junto com `docs/OPERATING_RULES.md` em programas com
essas superfícies.

## 1. Cadeia APK → gateway → config → terceiro (padrão High/Critical)

Comportamento observado:

1. App Android/TV hardcoda `Ocp-Apim-Subscription-Key` (ou equivalente) por ambiente (prod/qa/dev/uat).
2. Sem a key: edge (Akamai) devolve **403**. Com a key: rotas `core-api` / clientconfig abrem.
3. `clientconfig` (às vezes por `Platform=Roku|Android|...`) embute secrets de terceiros (Crowdin PAT, analytics, feature flags).
4. Mesma key de prod pode reaparecer em JS web (`_app` / Next bundles) — não assumir “só mobile”.
5. Impacto real = **cadeia**: key → config → token de terceiro com write authz (provar 400/404 em mutação, não 401/403).

Regras de caça:

- Extrair **todas** as `*ApiEnvironment` / `Subscription-Key` / `clientconfig` do jadx antes de fuzz cego.
- Testar cada env (prod/qa/dev) com a key correspondente; não misturar.
- Diferenciar secret **reportável** (PAT employee, write) vs N/A (Bitmovin license, Storyteller app id, Amplitude).
- Se o programa for popular: esperar **duplicate** em secrets óbvios do APK; priorizar cadeias/impactos menos óbvios ou authz pós-login.
- Após reportar/duplicar a cadeia: **não** reabrir o mesmo root cause; pivotar.

RoE: ao provar write em terceiro (Crowdin etc.), parar mutações destrutivas; evidência mínima.

## 2. CIAM / Identity API (Fastify-style)

Comportamentos:

- Envelope típico: `{"status":"success|error","data":{...},"errorCodes":[...]}`.
- Prefixo por ambiente: prod `/api/v1/`, dev `/dev/`, qa `/qa/` — **não** copiar paths entre hosts diferentes (`identity-server-*` ≠ `identity-*`).
- `GET /health` 200 + JSON 404 “Route GET:/x not found” = app vivo, path errado (não “morto”).
- Device pairing: `GET /devices/{id}/codes` unauth → código; impacto Low sem binding/ATO.
- Oracles de conta (enum):
  - `registrationStatus`: 400 “Profile not found” vs 200 `{isFull:true}`
  - `auth` / `otp/auth`: 401 `INVALID_CREDENTIALS` vs 403 `ACCOUNT_LOCKED`
  - `password/forgot` genérico 200 = controle negativo bom
- Profile autenticado exige `Authorization`; sem header → `INVALID_SESSION` (esperado).

Regras:

- Mapear paths do APK/jadx **antes** de wordlist genérica.
- Não spray de senha/OTP; 1–2 probes diferenciais bastam para enum.
- Hosts `identity-server-*` podem ser outro produto (só `/health`); não forçar `/api/v1` do CIAM.

## 3. ForgeRock / Ping AM (`/am/oauth2`, `/am/json`)

Comportamentos:

- OIDC metadata + JWKS + `serverinfo/*` públicos = esperado, sozinho não é bounty.
- Metadata pode anunciar grants perigosos (`password`, `client_credentials`) e scopes (`fr:idm:*`, `am-introspect-all-tokens`) — **sem `client_id` válido não há impacto**.
- Dynreg (`POST /am/oauth2/register`) pode responder `invalid_request` no GET e `access_denied` / “Access Token not valid” no POST → registro **não** aberto.
- `POST /am/json/realms/root/authenticate` (sem tree) → 200 com `NameCallback`+`PasswordCallback` + `authId` JWT HS256 (árvore default).
- Trees nomeadas (`login`, `ldapService`, `Registration`, …) → `No Configuration found` se não existirem.
- Realm `/alpha` vs `/` podem divergir (401 Login failure + `failureUrl`).
- XUI (`/am/XUI/`) muitas vezes **não** embute `client_id`; consumer login pode ser CIAM (`identity.*`) e ForgeRock ser só employee/dev.

Regras:

- Não gastar rate limit em authorize/token/PAR sem `client_id` minerado (JS login, Burp, runtime app).
- Mineração offline: APK + www account/sign-in + `id.*` bundles + captura `authorize?client_id=`.
- Invalid client → `invalid_client` confirma gate; não é bypass.

## 4. ADFS / Team Portal (employee)

Comportamentos:

- Hosts `teamdirectory` / `gamenotes` redirecionam para `teamportal.../discovery?appid=td|gn`.
- API ASP.NET: muitos `/api/*` → “No HTTP resource”; controller real devolve **“Authorization has been denied”** + 302 para `/discovery?ReturnUrl=...` (rota **existe**).
- Distinguir: 404 HTML “resource removed” = action inexistente; JSON auth-denied = action viva atrás de auth.
- Discovery: form email → `POST /Discovery/SignIn` → ADFS (`.../adfs/ls/`) com `wreply` **fixado** no portal (ReturnUrl externo na query **não** foi repassado ao ADFS no teste).
- Unauth sozinho ≠ finding; valor = sessão ADFS + IDOR/authz em `appid` / `/api/applications/*`.

Regras:

- Fuzz de controller: procurar o padrão “denied” vs 404 genérico.
- Não password-spray no discovery; um POST de email só para ver redirect ADFS/ReturnUrl.
- Sem cookies employee: documentar lead e pivotar (não round infinito unauth).

## 5. Client “gates” fracos (marketing APIs)

Padrão LockerVision-like:

- Endpoint público devolve “key” do dia (`GetValidKey` → base64 de data).
- Header cliente = `base64(uuid_hardcoded + "_" + DD/MM/YYYY)` (atenção ao formato da data).
- Sem header: 401; com header forjado: 200 em APIs de conteúdo público.
- Stack traces .NET = Info; dados públicos de marketing = Low/N/A sozinho.

Regra: se o “bypass” só abre conteúdo já público, não forçar Medium.

## 6. WordPress / legacy / Akamai

- `wp-json` users/drafts: 404 `rest_no_route` ou 401 em `context=edit` = locked.
- Media 200 com `status=inherit` + URLs CMS públicas = marketing, não draft privado.
- XML-RPC: 403/410 Wordfence-style ≠ method list.
- `cms.*` / roots com Akamai **403** em tudo: não insistir sem path evidenciado localmente.
- `content-api*` com **418** “Content Unavailable”: edge morto para unauth; não repetir health/graphql forever.

## 7. Mobile TVE / Adobe Pass (High potencial, device-gated)

Sinais estáticos (jadx):

- `ContentProvider` **exported** + `grantUriPermissions` + `openFile()` sem check de caller.
- URI tipica: `content://<pkg>.GlobalStorageProvider/databases/.adobepassdb_*`
- Deeplinks `gametime://game|event|videos` / WebView bridge.

Regra: **não reportar só com static**. Precisa adb: read pre/post login, strings de authn/authz/MVPD/token, e (se seguro) tamper com impacto em entitlement. Checklist device-local obrigatório.

## 8. Escopo / rate / OOS em programas grandes

- CSV H1 `eligible_for_submission=true` é fonte de verdade; hosts ricos podem estar **OOS** (`payment.*`, `ottapp-*`, foundations, etc.).
- Rate ≤3 req/s global: serializar Lane A; Codex/offline só arquivos locais; handshake `NOTIFY_CURSOR.txt` + `CODEX_DONE::`.
- Auth paths no JS (`/web/token`, evergent, MediaKind) podem apontar para hosts OOS — validar CSV antes de testar.
- Após duplicate do “jackpot” APK: ROI unauth cai; só continuar com device, sessão employee, ou takeover DNS one-shot.

## 9. Decisão de pivot (ROI)

Estacionar programa quando:

- High óbvio já foi duplicate;
- unauth Medium+ esgotado em 2–3 rounds;
- restante High exige artefato humano ausente (adb / ADFS / KYC).

Preferir: fechar draft já existente noutro alvo, ou programa com **2 contas** sem KYC (authz/IDOR).

## Checklist rápido (copiar para novo alvo similar)

```
[ ] jadx: keys APIM/gateway + clientconfig + providers exported + deeplinks
[ ] core/gateway: 403 sem key vs 200 com key; listar rotas úteis
[ ] clientconfig por Platform: secrets de terceiro; provar authz (não só presença)
[ ] www/_app: mesma key?
[ ] identity: paths do APK; enum diferencial; device codes
[ ] ForgeRock: metadata ok; NÃO fuzz token sem client_id
[ ] employee portal: denied-vs-404; discovery→ADFS; precisa sessão
[ ] WP/legacy: users/draft/media; parar se só marketing
[ ] device: Adobe Pass / storage provider só com adb
[ ] CSV OOS + rate limit antes de qualquer ferramenta
[ ] duplicate risk: não re-reportar mesma cadeia
```
