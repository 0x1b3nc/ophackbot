# How I Run Bug Bounty

## Default platform: Bugcrowd

I hunt and report on **Bugcrowd** by default. Notes: `bounty_knowledge/BUGCROWD.md`.

- Start a program from `bugcrowd.com/engagements/<slug>` or domain + brief
- Scope goes in `targets/<slug>/SCOPE.md`
- Severity = **VRT**, not generic CVSS
- Required researcher headers: write them down and send them on every test request
- HackerOne is fine if I (or the link) point there

## What I'm trying to do

Same loop for every program:

1. reconFTW as the wide recon orchestrator, using tools I already have installed
2. pick real targets / promising flows from that output
3. drop into HexStrike + Burp for focused validation, replay, PoC, report

## How I like to work

I go hard on coverage and depth, but only inside what the program allows.
I don't sit in "passive audit forever" mode. After negatives on the same vector I pivot.
I use `bounty_knowledge/` and the toolchain (reconFTW, PD stack, nuclei, ffuf, HexStrike/Burp) instead of replaying the same curl forever.

Feedback I keep (2026-07-10): don't be abstract. Every cycle = falsifiable hypothesis + concrete stack tool + evidence. Inventories with no impact don't count as hunting. Citing tools without using them is a fail. Open the note, run the thing.

### Local evidence before I claim anything

Cursor, Codex, and any other agent in this workspace share disk, not memory.
Before I assert scope, category, severity, exploitability, report strategy, or next attack plan, I check local material first.

Order:

1. `WORKSPACE_STATE.md` or my private equivalent
2. Target files under `targets/<program>/`: `PLAN.md`, `SCOPE.md`, `FINDINGS.md`, `RESUME.md`, reports, attachments, recon
3. `bounty_knowledge/study_notes/INDEX.md` and the matching tech note
4. Prior reports, triage replies, local lessons for similar patterns

If local files don't back the claim, I say:
`this is inference, not confirmed yet`.

No vibes-only advice. Important recommendations point at scope text, endpoint/request, account evidence, a studied technique, or proven/missing impact.

### Authz does not stop at GET/read

I don't limit IDOR/BOLA to `GET` or read paths. I also hit state-changing ops:

- `PATCH`
- `PUT`
- sensitive `POST`
- `DELETE`
- GraphQL `mutation`

Heuristic I trust: devs usually protect read better than write. I look for `BOLA` (wrong object) + `BFLA` (wrong action/role) on the same op, especially GraphQL mutations and admin/account flows.

Minimum matrix for every write/mutation:

1. swap object ID (`BOLA`)
2. swap session/role (`BFLA`)
3. swap both

I don't stop at "A can read B". I check whether A can change / delete / disable / lock / change role / touch lifecycle of B.

In GraphQL I start with mutations that take IDs and change state. Triagers often expect introspection noise; I want real write impact.

### Don't mark DEEP until I actually studied it

In study sessions I don't stamp a source **DEEP** after skimming the home page.
I read the main page, relevant subpaths, files, and articles. For repos I clone or inventory the tree before synthesizing. For big blogs I keep a backlog and leave items pending until I really read them.

If it's too big for one session I log progress: what I read, what's left. I don't fake "studied everything" from a README.

Study phase = learn and write notes. Scope restriction applies when I'm attacking a real target, not when I'm reading and organizing knowledge.

On programs that means:

- map a lot of surface
- chase forgotten routes, APIs, params, JS, auth flows, half-finished states
- prioritize auth, account, payment, org, certs, files, admin, integrations, IDs
- test hypotheses fast
- document evidence when something real shows up
- check TOOLCHAIN + Bug-Bounty-Agents personas + awesome-bugbounty-tools before inventing ad-hoc probes

Aggression isn't a fixed personality. Each bounty has its own rules. Before high-impact tests I re-read scope and do exactly what it allows.

### Aggression levels (0-3) before any active command

From my study notes + guide. **Aggression only goes up with policy, never by default.**

Before any command that hits a program target I state:

1. **Level 0-3** for that action
2. **Quote** from `targets/<slug>/SCOPE.md` (or policy) that allows it

No clear quote → most conservative level. Outside SCOPE → no level at all.

| Level | Name | Examples | When |
|-------|------|----------|------|
| **0** | Passive | OSINT, crt.sh, Wayback, GitHub dork, public JS, indexed Shodan | Always; findings only go active after the asset is in SCOPE |
| **1** | Light active | `subfinder`, `dnsx`, `httpx`, shallow `katana`, fingerprint | Default after asset confirmed; low rate (~10-20 rps, c 5-10) |
| **2** | Moderate active | controlled `ffuf`, normal nuclei (no `dos`/`fuzz`), one-param injection, IDOR A/B | In-scope asset + policy doesn't ban automated scanning |
| **3** | Aggressive | high concurrency, brute, multi-req race, `nuclei -itags dos` | Only with **explicit** policy text; re-read before running |

Hardware ceiling is separate: I still run `nuclei -c 5-10 -rl 10-30` even if policy allows 3. Take the lower of scope ceiling and hardware ceiling.

Study notes live in `bounty_knowledge/study_notes/INDEX.md`.

Only if the program explicitly allows it do I touch:

- controlled brute force
- rate-limit stress
- DoS
- high-volume fuzz
- high-cadence active scanners

No clear allow → treat as banned.

By default, without clear auth, I don't do:

- DoS
- brute force
- credential stuffing
- anti-abuse bypass outside what's allowed
- form spam
- fake company/KYC/payment data
- out-of-scope assets
- destructive exploitation
- real purchases, submissions, or irreversible actions

## My default stack

### JADX / big APKs

I don't open full JADX GUI as the default on a big/obfuscated APK. That already froze my whole session once.

- Search already-extracted artifacts and scoped paths first
- Single class: `recon_tools/jadx_single_class.sh <Class> <apk> <out>`
- Broad searchable dump: `recon_tools/jadx_full_safe.sh <apk> <out>` (CLI, limited heap/threads, `fallback` by default)
- `jadx-gui` only as exception via `recon_tools/jadx_gui_light.sh <apk> --select-class <Class>`
- If readable/simple dies, keep `fallback` as the full index for `rg`, then pull classes as needed
- Never repo-wide search across huge JADX dumps; stay inside the target/export dir

### 1. reconFTW for wide surface

I use reconFTW as the early radar until I have a real candidate. It's an orchestrator, not an excuse to reinstall my whole toolchain.

Install rules:

- no broad installer "just because"
- don't reinstall Go, Python, nuclei, subfinder, httpx, katana, ffuf, arjun if they already work
- check `which` / `--version` before installing
- only install the missing dep that blocks a specific reconFTW mode
- no Docker

Tools I expect reconFTW to reuse:

- ProjectDiscovery: `subfinder`, `httpx`, `katana`, `nuclei` (scope-appropriate), `naabu` only when port scan is allowed
- Amass when the program is a big domain/company and asset discovery matters
- Also: `ffuf`, `arjun`, wayback/gau-style history, manual JS when it's a rich SPA/API

What I want out:

- live hosts
- interesting endpoints
- important JS
- auth routes
- APIs with params
- candidates for manual work

### 2. Target selection

I prioritize:

- login / authenticated state
- account/org workflows
- predictable IDs
- sensitive functions
- upload/download
- invites, certs, payments, reports, private data
- APIs returning `code: 00`, `success: true`, rich data, or differential errors

I don't waste time on:

- static landing pages
- public docs
- pure marketing
- SPA shell-only endpoints
- scanners making noise with no hypothesis

### 3. HexStrike + Burp for focused validation

When I have a candidate:

- capture the flow in Burp
- export XML if needed
- parse request/response
- redact tokens/cookies before sharing
- reproduce with controlled scripts
- compare states: no login, incomplete login, account A, account B, different roles
- build a minimal PoC
- keep negative control evidence separate from vulnerable evidence

### 4. Report

I only report when I have:

- clear preconditions
- expected behavior
- observed behavior
- plausible impact
- short repro steps
- evidence without live session secrets
- a severity I can defend

## Aggression per program

I set intensity per program:

- read policy/scope first
- note what's allowed
- note what's banned
- fit recon / HexStrike / Burp to that program's limit
- if DoS/brute/rate-limit are allowed, document that permission before testing
- if unsure, stay moderate until confirmed

Usually fine on common bounties:

- moderate crawling
- param enum on the app's own endpoints
- nuclei at low/medium rate when allowed
- A/B with my own test accounts
- replay of captured requests
- non-destructive ID variation
- read/authz validation

High-impact only when explicitly authorized:

- brute force
- DoS
- stress
- high volume
- mass account creation
- aggressive rate-limit probing
- heavy fuzz

Even when authorized I keep evidence, scope, and control. No third-party creds, no changing/deleting other people's data without explicit permission, no scope creep.

## Decision shortcuts

- Still wide → reconFTW first with local tools
- Already have a suspicious endpoint/flow → HexStrike + Burp
- Need impact proof → controlled script + redacted evidence
- Needs real company, KYC, payment, or irreversible action → stop and switch targets unless the program explicitly allows it

## Evidence I keep

Keep:

- redacted request
- redacted response
- screenshot
- negative control
- account/role state
- simple PoC
- short technical summary

Don't put in a public report:

- cookies
- bearer tokens
- session IDs
- live CSRF tokens
- raw Burp XML with session
- more PII than needed

## Knowledge base and AI agents

Stuff I keep under `bounty_knowledge/` and `.cursor/rules/`:

- **Bug-Bounty-Agents**: personas in `.cursor/rules/`. Reinstall with `./bounty_knowledge/Bug-Bounty-Agents/install.sh --target cursor` after updating
- **awesome-bugbounty-tools**: check before installing new toys
- **awesome-ai-security** (+ variants): when LLM/chatbot is in scope
- **awesome-agent-skills-security**: agent/skill security (not an offensive playbook)

Local index:

- `bounty_knowledge/README.md`
- `bounty_knowledge/TOOLCHAIN.md`
- `.cursor/skills/bug-bounty-workflow/SKILL.md` (if present)

Quick persona routing:

| Phase | Persona in `.cursor/rules/` |
|------|----------------------------|
| Scope/plan | `engagement-planner`, `bug-bounty` |
| Recon | `recon-advisor` |
| Web/API | `web-hunter`, `api-security` |
| IDOR/logic | `bizlogic-hunter` |
| PoC | `poc-validator` |
| Report | `report-generator` |

Personas help; these operating rules stay mandatory (reconFTW, HexStrike, Burp, program limits).

If `.cursor/rules/01-bounty-autopilot.mdc` is present, agents should route personas without me naming them every time.

## Lessons I reuse (mobile / API / auth)

Full file: `bounty_knowledge/LESSONS_MOBILE_API_AUTH.md`.

I re-read it on programs with APK, Azure APIM, CIAM/identity, ForgeRock/Ping, ADFS/employee portal, Adobe Pass/TVE, or legacy WP behind Akamai.

### Mobile → gateway → config → third party
- APIM / `Subscription-Key` in the APK (sometimes web JS too) bypasses edge 403 and opens `clientconfig`
- Reportable impact = chain into a third-party secret with write authz (prove 400/404 schema, not just 401/403)
- Split High secrets (employee PAT) from N/A (player license, Storyteller id, analytics)
- Popular programs: expect **duplicate** on the obvious APK jackpot; don't reopen the same chain after duplicate

### CIAM / identity
- Envelope `status/data/errorCodes`; prefixes `/api/v1` vs `/dev` vs `/qa` per host
- JSON 404 "Route GET:/x not found" + `/health` 200 = alive app, wrong path (other product may be `identity-server-*`)
- Enum via differential `registrationStatus` / `auth` / `otp`; generic `password/forgot` = control
- Unauth device pairing codes = Low without ATO/binding

### ForgeRock / AM
- Public metadata/JWKS/serverinfo alone ≠ bounty
- "Dangerous" grants/scopes in discovery **without client_id** = no impact
- Dynreg may need access token (`access_denied`); password/CC grant fails with `invalid_client`
- Don't burn rate on authorize/token/PAR until I mine `client_id` (JS/Burp/runtime)
- Consumer login may be CIAM; ForgeRock may be employee/dev only

### ADFS / team portal
- "Authorization has been denied" + 302 discovery = **real controller** (not generic ASP.NET 404)
- `appid` + ReturnUrl: check if ADFS wreply accepts external; in the case I studied, wreply stayed fixed on the portal
- Unauth = lead; bounty needs employee session + authz/IDOR

### Weak client gates
- Daily header `base64(uuid + "_" + date)` from a public endpoint = cosmetic bypass if data is already public (Low/Info)

### WP / Akamai / content edge
- users/draft locked; public `inherit` media = don't report; XML-RPC 403/410; 418 content-unavailable = stop repeating

### Adobe Pass / exported ContentProvider
- Static (exported + openFile without caller check) is **not enough**; need adb PoC pre/post login and impact on authn/authz/entitlement

### SSRF: DNS rebinding (my note 2026-07-12)
Ref: H1 [#1369312](https://hackerone.com/reports/1369312) + `bounty_knowledge/study_notes/web-vulns/ssrf.md`.

When there's a URL sink (fetch/import/webhook/preview/og/avatar/callback) I don't stop at:

- OAST that only hit DNS
- direct `127.0.0.1` / metadata blocked

I try **DNS rebinding TOCTOU** if the app checks host/IP then fetches later (second resolve):

1. Domain I control, low TTL / rebind A: 1st answer = "safe" public IP, 2nd = `127.0.0.1` / RFC1918 / `169.254.169.254`
2. Tools: `rbndr.us`, `1u.ms`, Singularity, or my own DNS (two A with TTL 0–1s)
3. Falsifiable hypothesis: filter passes check, internal fetch changes. Evidence = internal OAST, body, timing, or differential error
4. Parallel: open redirect on allowlist, 302 after check, IP bypass (`127.1`, IPv6, dword, `@`, etc.)

No mapped URL sink → find the sink first (JS / `url=` / webhook). Rebind doesn't invent SSRF from nothing.

### ROI / pivot
- Hard rate limit (e.g. ≤3 rps) + huge scope + High gated behind device/ADFS/KYC → park after 2–3 unauth rounds with no Medium+
- Prefer a program with 2 accounts and no KYC, or finish an existing draft, over more unauth fuzz

Dual-agent handshake (when I use it): Codex offline, zero HTTP to the target; when done: `CODEX_DONE::<task>::<file>` + `STATUS.md` DONE + `LANE_A_WAKE.md` + `NOTIFY_CURSOR.txt` first line `READY`. Cursor can wake from the watcher without me babysitting.

## Mini report after every stage

When I (or an agent) finish a stage on a program, I send a short mini report:

- stage done
- tools used
- study materials opened
- why I chose that line of attack
- objective results
- continue, pivot, or need my input

I also drop the same summary into the target folder when it creates reusable context. I don't want to depend on chat memory.
