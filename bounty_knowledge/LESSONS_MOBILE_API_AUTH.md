# Lessons I Reuse: Mobile / API / Auth

Source: patterns I keep hitting on APK, CIAM, ForgeRock/ADFS, APIM, and employee portals.
I re-read this with `docs/OPERATING_RULES.md` on programs that look like this.

## 1. APK → gateway → config → third party (High/Critical pattern)

What I've seen:

1. Android/TV app hardcodes `Ocp-Apim-Subscription-Key` (or equivalent) per env (prod/qa/dev/uat).
2. Without the key: edge (Akamai) returns **403**. With the key: `core-api` / clientconfig open up.
3. `clientconfig` (sometimes by `Platform=Roku|Android|...`) embeds third-party secrets (Crowdin PAT, analytics, feature flags).
4. Same prod key can show up in web JS (`_app` / Next bundles). I don't assume "mobile only".
5. Real impact = **chain**: key → config → third-party token with write authz (prove 400/404 on mutation, not just 401/403).

How I hunt it:

- Extract **all** `*ApiEnvironment` / `Subscription-Key` / `clientconfig` from jadx before blind fuzz
- Test each env with the matching key; don't mix
- Split reportable secrets (employee PAT, write) from N/A (Bitmovin license, Storyteller app id, Amplitude)
- Popular programs: expect **duplicate** on the obvious APK jackpot; chase less obvious chains or post-login authz
- After I report/duplicate that chain: **don't** reopen the same root cause; pivot

RoE: when I prove write on a third party (Crowdin etc.), I stop destructive mutations; minimal evidence only.

## 2. CIAM / Identity API (Fastify-style)

Behaviors:

- Typical envelope: `{"status":"success|error","data":{...},"errorCodes":[...]}`
- Env prefixes: prod `/api/v1/`, dev `/dev/`, qa `/qa/` — I don't copy paths across hosts (`identity-server-*` ≠ `identity-*`)
- `GET /health` 200 + JSON 404 "Route GET:/x not found" = app alive, wrong path (not "dead")
- Device pairing: `GET /devices/{id}/codes` unauth → code; Low impact without binding/ATO
- Account oracles:
  - `registrationStatus`: 400 "Profile not found" vs 200 `{isFull:true}`
  - `auth` / `otp/auth`: 401 `INVALID_CREDENTIALS` vs 403 `ACCOUNT_LOCKED`
  - generic `password/forgot` 200 = good negative control
- Authenticated profile needs `Authorization`; no header → `INVALID_SESSION` (expected)

Rules I follow:

- Map paths from APK/jadx **before** a generic wordlist
- No password/OTP spray; 1–2 differential probes are enough for enum
- `identity-server-*` hosts may be another product (only `/health`); I don't force CIAM `/api/v1` onto them

## 3. ForgeRock / Ping AM (`/am/oauth2`, `/am/json`)

Behaviors:

- Public OIDC metadata + JWKS + `serverinfo/*` = expected, alone not a bounty
- Metadata may advertise dangerous grants (`password`, `client_credentials`) and scopes (`fr:idm:*`, `am-introspect-all-tokens`) — **no valid `client_id` means no impact**
- Dynreg (`POST /am/oauth2/register`) may return `invalid_request` on GET and `access_denied` / "Access Token not valid" on POST → registration is **not** open
- `POST /am/json/realms/root/authenticate` (no tree) → 200 with `NameCallback`+`PasswordCallback` + HS256 `authId` JWT (default tree)
- Named trees (`login`, `ldapService`, `Registration`, …) → `No Configuration found` if missing
- Realm `/alpha` vs `/` can diverge (401 Login failure + `failureUrl`)
- XUI (`/am/XUI/`) often **doesn't** embed `client_id`; consumer login may be CIAM (`identity.*`) and ForgeRock employee/dev only

Rules:

- Don't burn rate limit on authorize/token/PAR without a mined `client_id` (login JS, Burp, runtime app)
- Offline mining: APK + www account/sign-in + `id.*` bundles + capture `authorize?client_id=`
- `invalid_client` confirms the gate; not a bypass

## 4. ADFS / Team Portal (employee)

Behaviors:

- Hosts like `teamdirectory` / `gamenotes` redirect to `teamportal.../discovery?appid=td|gn`
- ASP.NET API: many `/api/*` → "No HTTP resource"; real controller returns **"Authorization has been denied"** + 302 to `/discovery?ReturnUrl=...` (route **exists**)
- Distinguish: 404 HTML "resource removed" = missing action; JSON auth-denied = live action behind auth
- Discovery: email form → `POST /Discovery/SignIn` → ADFS (`.../adfs/ls/`) with `wreply` **fixed** on the portal (external ReturnUrl in query was **not** passed to ADFS in my test)
- Unauth alone ≠ finding; value = ADFS session + IDOR/authz on `appid` / `/api/applications/*`

Rules:

- Controller fuzz: hunt "denied" vs generic 404
- No password spray on discovery; one email POST just to see ADFS/ReturnUrl redirect
- Without employee cookies: document the lead and pivot (no infinite unauth rounds)

## 5. Weak client "gates" (marketing APIs)

LockerVision-like pattern:

- Public endpoint returns a daily "key" (`GetValidKey` → base64 of date)
- Client header = `base64(uuid_hardcoded + "_" + DD/MM/YYYY)` (watch date format)
- No header: 401; forged header: 200 on public content APIs
- .NET stack traces = Info; public marketing data alone = Low/N/A

Rule: if the "bypass" only opens already-public content, I don't force Medium.

## 6. WordPress / legacy / Akamai

- `wp-json` users/drafts: 404 `rest_no_route` or 401 on `context=edit` = locked
- Media 200 with `status=inherit` + public CMS URLs = marketing, not private draft
- XML-RPC: 403/410 Wordfence-style ≠ method list
- `cms.*` / roots with Akamai **403** everywhere: I don't insist without a locally evidenced path
- `content-api*` with **418** "Content Unavailable": dead edge for unauth; I don't spam health/graphql forever

## 7. Mobile TVE / Adobe Pass (High potential, device-gated)

Static signals (jadx):

- Exported `ContentProvider` + `grantUriPermissions` + `openFile()` with no caller check
- Typical URI: `content://<pkg>.GlobalStorageProvider/databases/.adobepassdb_*`
- Deeplinks `gametime://game|event|videos` / WebView bridge

Rule: **I don't report static alone**. I need adb: read pre/post login, authn/authz/MVPD/token strings, and (if safe) tamper with entitlement impact. Device-local checklist is mandatory.

## 8. Scope / rate / OOS on big programs

- H1 CSV `eligible_for_submission=true` is truth; rich hosts can still be **OOS** (`payment.*`, `ottapp-*`, foundations, etc.)
- Rate ≤3 rps global: serialize Lane A; Codex/offline = local files only; handshake `NOTIFY_CURSOR.txt` + `CODEX_DONE::`
- Auth paths in JS (`/web/token`, evergent, MediaKind) may point at OOS hosts — validate CSV before testing
- After the APK "jackpot" duplicates: unauth ROI drops; I only continue with device, employee session, or one-shot DNS takeover

## 9. When I pivot (ROI)

I park a program when:

- The obvious High already duplicated
- Unauth Medium+ is exhausted in 2–3 rounds
- Remaining High needs a human artifact I don't have (adb / ADFS / KYC)

I prefer: finish an existing draft on another target, or a program with **2 accounts** and no KYC (authz/IDOR).

## Quick checklist (copy into a similar new target)

```
[ ] jadx: APIM/gateway keys + clientconfig + exported providers + deeplinks
[ ] core/gateway: 403 without key vs 200 with key; list useful routes
[ ] clientconfig by Platform: third-party secrets; prove authz (not just presence)
[ ] www/_app: same key?
[ ] identity: APK paths; differential enum; device codes
[ ] ForgeRock: metadata ok; DON'T fuzz token without client_id
[ ] employee portal: denied-vs-404; discovery→ADFS; needs session
[ ] WP/legacy: users/draft/media; stop if it's only marketing
[ ] device: Adobe Pass / storage provider only with adb
[ ] CSV OOS + rate limit before any tool
[ ] duplicate risk: don't re-report the same chain
```
