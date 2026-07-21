# How I Study Web Hacking & Bug Bounty (HackerOne / Bugcrowd) — v2

What changed in this version: denser tech notes per vuln class (section 4), an
explicit **aggression level** framework tied to documented scope (section 0.1),
and agent instructions so any AI declares the level (and quotes the policy) before
active commands. Sections 1–3, 5–6, 8–9 are the same idea, just tighter.

Curated legit sources for offensive security research, focused on official bounty
programs, plus a study plan I run with agents on a modest Kali VM.

Sections 1–7 = **what** I study. Section 8 = **how** an agent should study it on
my hardware, and **how hard**, given scope.

---

## 0. Scope is law

Applies to me and anything an agent suggests or automates:

- Read the program security policy/scope **before** any active test. In/out of scope and banned test types (DoS, social eng, etc.) vary a lot.
- Save the policy link locally (see folder layout in 8.3) before testing.
- Respect rate limits. Over-aggressive scanning is the fastest ban. Without auth it isn't bounty, it's unauthorized access.
- If I stumble on third-party data, take the minimum needed to prove impact. No bulk exfil.
- Public disclosure (blog, Twitter, etc.) only after formal platform approval.

### 0.1 Golden rule: aggression scales with scope, never by default

"Be more aggressive" (higher concurrency, deeper fuzz, brute, race floods, intrusive nuclei tags) is only an option **after** the documented program scope says that kind of test is allowed on that asset. Otherwise I stay at the most conservative level. Intensity is earned by reading policy, not by tool defaults.

Four levels before I run anything:

- **Level 0 — Passive** (always ok, never touches the target directly): OSINT, Google dorks, crt.sh, Wayback, GitHub secret dorks, Shodan/Censys indexed data, client-side RE of a published app. Fine before 100% scope confirm, but findings only go active after they're in `scope.md`.

- **Level 1 — Light active** (default once `programs/<name>/scope.md` confirms the asset): active subdomain enum (`subfinder`, `dnsx`), simple HTTP probe (`httpx`), polite crawl (`katana` shallow), tech fingerprint, security headers. Low rate by default (~10-20 rps, concurrency 5-10).

- **Level 2 — Moderate active** (asset explicitly in scope + policy doesn't ban automated scanning): dir/param fuzz with `ffuf` + SecLists, manual injection one field at a time, nuclei with default template set (already excludes `dos`/`fuzz` by default; see 8.6), IDOR/BAC swapping IDs between my own test accounts.

- **Level 3 — Aggressive** (only when policy is explicit: no ban on high volume / heavy scanning / brute, accepts controlled DoS-adjacent tests): high-concurrency fuzz, brute where allowed (coupons, rate-limit bypass), multi-request races, nuclei with normally excluded tags via `-itags dos` (re-read policy twice). Aggressive means **max intensity the scope allows**, not "no rules".

**Outside documented scope = no level.** Similar subdomain, same IP range, same parent company: still need explicit confirmation. Never inference.

---

## 1. HackerOne — official stuff I use

- **Program directory** — https://hackerone.com/directory/programs  
  Searchable public programs, filters by asset type and bounty. Where I pick targets.

- **Hacktivity** — https://hackerone.com/hacktivity  
  Disclosed reports. Highest learning density for me: full repro, payout, severity. Filter Disclosed, sort by severity.

- **Hacker101 + CTF** — https://www.hacker101.com/ and https://ctf.hacker101.com/  
  Free H1 training + CTF. 26 CTF points unlocks private invites. 500 reputation can redeem Burp Pro trial.

- **reddelexc/hackerone-reports** — https://github.com/reddelexc/hackerone-reports  
  Aggregated disclosed reports by bug type/program. Good for batch study without the Hacktivity UI.

## 2. Bugcrowd — official stuff I use

- **Engagements** — https://bugcrowd.com/engagements (needs account) or public list https://www.bugcrowd.com/bug-bounty-list/

- **CrowdStream** — https://bugcrowd.com/crowdstream  
  Bugcrowd's Hacktivity equivalent: accepted/disclosed submissions with VRT priority.

- **Bugcrowd University** — https://github.com/bugcrowd/bugcrowd_university  
  Free official Markdown modules. Easy for agents to read without weird parsing.

- **VRT** — https://github.com/bugcrowd/vulnerability-rating-taxonomy (browse: https://bugcrowd.com/vulnerability-rating-taxonomy)  
  How Bugcrowd rates P1–P5 per class. I calibrate reports against this. Section 4 maps typical P1–P5, but VRT is more granular (blind vs full-read SSRF, etc.).

## 3. Web security foundations (both platforms)

- **PortSwigger Web Security Academy** — https://portswigger.net/web-security  
  Free labs + learning paths. Still the densest free material. Section 4 follows the same class split.

- **HackTricks** — https://book.hacktricks.wiki/  
  Huge community wiki with ready commands/payloads. More cheatsheet than course. Cloud fork: https://cloud.hacktricks.wiki/

- **OWASP WSTG** — https://github.com/OWASP/wstg  
  Formal methodology + checklist. Good master index (WSTG-INFO-02 style IDs).

- **OWASP Top 10** — https://owasp.org/www-project-top-ten/

- **OWASP API Security Top 10 (2023)** — https://owasp.org/API-Security/  
  Most modern H1/BC scope is API. Current list:
  1. API1:2023 – BOLA  
  2. API2:2023 – Broken Authentication  
  3. API3:2023 – Broken Object Property Level Authorization  
  4. API4:2023 – Unrestricted Resource Consumption  
  5. API5:2023 – BFLA  
  6. API6:2023 – Unrestricted Access to Sensitive Business Flows  
  7. API7:2023 – SSRF  
  8. API8:2023 – Security Misconfiguration  
  9. API9:2023 – Improper Inventory Management  
  10. API10:2023 – Unsafe Consumption of APIs  

  BOLA alone is a huge chunk of paid API findings. First place I look on a new endpoint.

## 4. Vuln classes — technical depth

This doesn't replace PortSwigger/OWASP/HackTricks. It's my synthesis layer (see 8.2: "40-50 of my notes, not 500 saved links"). Each block: what it is, where I look, common bypasses, typical aggression (0.1), typical VRT.

### 4.1 Injection (SQLi, NoSQLi, Command, SSTI, XXE)

- **SQLi**: error/union plus **blind** (boolean/time) and **second-order**. Beyond obvious forms: headers (`X-Forwarded-For`, `User-Agent`), sort/filter API params, autocomplete search.
- **NoSQLi**: injectable JSON ops (`$ne`, `$gt`, `$regex`) when the backend parses body types blindly. String field accepting `{"$ne": null}` is a tell.
- **Command injection**: anything shelling out (image/PDF convert, embedded ping, report gen). Separators `;` `|` `&&` backtick; filter bypasses if blocked.
- **SSTI**: dynamic templates (display name, email/PDF). Math probe `{{7*7}}` / `${7*7}` / `#{7*7}`; if it evaluates, identify engine, then gadgets.
- **XXE**: XML endpoints (upload, SOAP, sometimes SVG). External entity to local file; if blocked, OOB DTD + Collaborator/OAST.
- **Aggression**: level 2 for most (one payload at a time). Automated all-param fuzz is high level 2; watch concurrency.
- **Typical severity**: proven code exec SQLi/SSTI/CMDi → usually P1. Local-file-only XXE without OOB → P2–P3 depending on file.

### 4.2 Auth, session, tokens

- **JWT**: `alg: none`, RS256→HS256 confusion (if algo not pinned), `kid` injection (path/SQLi if used for key lookup).
- **OAuth**: weak `redirect_uri` (open subdomain, extra params, `startswith` instead of exact), missing/unchecked `state`, auth code reuse.
- **Password reset / magic link**: predictable token, no expiry / not one-time, token accepted if email matches without binding.
- **Session fixation**: session ID must change after login.
- **Aggression**: level 1–2 manual. Short reset-token brute is level 3 (needs volume + explicit brute allow).
- **Typical severity**: full ATO without interaction → P1. OAuth CSRF without 2FA → often P2.

### 4.3 Authz (IDOR/BAC, mass assignment, priv esc)

- **IDOR/BAC**: swap identifier between my test accounts; cover read, write, and function (BFLA / API5). GraphQL fails per field/resolver too.
- **Mass assignment**: extra JSON fields the form doesn't expose (`role`, `isVerified`, `balance`).
- **Horizontal vs vertical**: I always want ≥2 accounts at different privilege levels.
- **Aggression**: level 1–2. Swapping my own IDs isn't high volume.
- **Typical severity**: IDOR leaking any user's PII → usually P1–P2. Non-sensitive internal counters → P3–P4.

### 4.4 SSRF

- Classic sinks: webhooks, PDF/thumbnail from URL, link preview, any user-supplied URL fetch.
- Internal targets: cloud metadata `169.254.169.254` (paths/headers differ AWS/GCP/Azure), internal ports, disguised localhost.
- Filter bypasses: decimal/octal/hex IP, redirect chains, DNS rebinding, `@` in URL.
- Blind: confirm with OOB (interactsh / Collaborator).
- **Aggression**: level 2 for single-payload manual. Level 3 only if I need wide internal port sweeps (usually avoidable).
- **Typical severity**: cloud metadata + creds → P1. Blind without sensitive read → P2–P3.

### 4.5 Race conditions and business logic

- **TOCTOU**: check-then-act flows (balance, coupon, attempt limits). Fire many requests at once, not sequentially.
- **Single-packet / last-byte sync**: Turbo Intruder style; shrinks the race window.
- Hunt first: coupons, referrals, should-be-idempotent like/follow, limited resources, money/credit.
- **Aggression**: level 3 by definition. Start with 5–10 parallel, then scale; clean up duplicated state if the program doesn't say otherwise.
- **Typical severity**: direct financial race → usually P1–P2. Harmless duplication → P4–P5.

### 4.6 Subdomain takeover and recon bugs

- Mechanics: DNS (often CNAME) points at abandoned third-party hosting; claim it, serve content on victim subdomain.
- At scale: `subfinder` → `dnsx` CNAMEs → `nuclei -t takeovers/` or dedicated tools.
- Confirm without being a jerk: claim for proof, minimal `index.html`, tear down after accept.
- **Aggression**: level 1.
- **Typical severity**: depends on what the subdomain is worth. Cookie/session-sharing main subdomain → P1–P2. Forgotten dead sub → P4.

### 4.7 API-specific: GraphQL, smuggling, cache poisoning

- **GraphQL**: prod introspection (`__schema`); field suggestion leaks schema; batching to bypass per-request rate limits; deep/alias abuse for resource exhaustion (API4/API6).
- **Request smuggling**: CL.TE / TE.CL / TE.TE desync. Study PortSwigger path hard before live programs; easy to hurt other users.
- **Cache poisoning**: unkeyed headers reflected and cached (`X-Forwarded-Host`, etc.).
- **Aggression**: introspection = level 1. Batching/cache poison = level 2. Smuggling = level 2–3 with extra care; re-read "may affect other users" policy.
- **Typical severity**: smuggling to session hijack → P1. Cached XSS → P1–P2. Bare introspection → often P4/info unless schema itself is sensitive.

### 4.8 Client-side: prototype pollution, DOM XSS, postMessage

- **Prototype pollution**: bad recursive merges accepting `__proto__` / `constructor.prototype`.
- **DOM XSS**: sources (`location.*`, `postMessage`, `referrer`) into sinks (`innerHTML`, `eval`, `document.write`, `on*`).
- **Unsafe postMessage**: `message` listener without `event.origin` checks.
- **Aggression**: level 1–2 (sometimes level 0 if JS is already public).
- **Typical severity**: DOM XSS without victim interaction → P2–P3. Server-side PP to RCE → P1.

## 5. Recon / hunting methodology

- **TBHM** — https://github.com/jhaddix/tbhm  
  Haddix slides/PDFs, recon → discovery → exploit methodology.

- **Pentester Land writeups** — https://pentester.land/writeups/  
  Searchable writeups by tag/program/payout.

- **Think in chains, not isolated bugs**: big payouts usually glue 2–3 mediums. When I study a writeup I ask which pieces made the chain and what each alone would have paid.

## 6. Real writeup banks

- **ngalongc/bug-bounty-reference** — https://github.com/ngalongc/bug-bounty-reference
- **devanshbatham/Awesome-Bugbounty-Writeups** — https://github.com/devanshbatham/Awesome-Bugbounty-Writeups

## 7. Payloads, wordlists, light tools

- **PayloadsAllTheThings** — https://github.com/swisskyrepo/PayloadsAllTheThings  
  On Kali: `sudo apt install payloadsallthethings`

- **SecLists** — https://github.com/danielmiessler/SecLists  
  Full clone ~1.4GB. Prefer `sudo apt install seclists` → `/usr/share/seclists`

- **ProjectDiscovery** — https://github.com/projectdiscovery  
  `subfinder`, `dnsx`, `naabu`, `httpx`, `katana`, `nuclei`. Typical pipe:  
  `subfinder -d target.com -silent | dnsx -silent | httpx -silent | nuclei -silent`  
  Install: `pdtm -ia`  
  Nuclei aggression: defaults already exclude `dos`/`fuzz`; unlock with `-itags` only at level 3 with policy. I keep `-rl 10-30` and `-c 5-10` on a weak VM even when scope allows 3.

- **ffuf** — https://github.com/ffuf/ffuf

---

## 8. How agents should study this for me

### 8.1 What runs where

Agent reasoning can be cloud-side. Local VM cost is disk, bandwidth, RAM for tools. Think plenty; clone/scan carefully.

### 8.2 Study principles

1. **Text > video**
2. **Synthesize, don't hoard**: ~40–50 of my notes I can re-read in 30s, not 500 bookmarks
3. **Layers**: foundations → recon methodology → vuln classes (section 4 + PAT + WSTG) → real reports
4. **Every note ends in "how I report this"** (VRT)
5. **Every active action declares level first** and quotes policy. No quote → most conservative level

### 8.3 Folder layout I like

```
~/bugbounty-study/
├── AGENTS.md
├── knowledge-base/
│   ├── INDEX.md
│   ├── recon/
│   ├── web-vulns/
│   ├── api-security/
│   └── reports-studied/
├── refs/
├── tools/
└── programs/
    └── <program-name>/
        ├── scope.md
        ├── recon-notes.md
        └── findings.md
```

(This kit already mirrors a lot of that under `bounty_knowledge/study_notes/` and `targets/`.)

### 8.4 What I want in AGENTS.md

- Read the whole source before writing notes
- Rewrite in own words; short payloads/commands can be literal
- Note template: What / Where / Common bypasses / PoC / Aggression 0-3 / VRT / Sources
- Update existing notes instead of duplicating
- Before active traffic: confirm asset in scope, declare level, quote policy

### 8.5 Study loop prompts I reuse

New source:

> Read [URL or path]. Summarize into `knowledge-base/<cat>/<topic>.md` with the AGENTS.md template (include aggression level + VRT). Don't paste big blocks. At most 2–3 payload/command examples. Add a line to INDEX.md.

Disclosed report:

> Read this disclosed report: [URL]. In `reports-studied/`, log: initial hypothesis, recon step that found it, which bugs chained (if any), and what would change with protection X.

### 8.6 Weak-VM care

- `git clone --depth 1` when I'm only reading
- Prefer apt packages over cloning SecLists/PAT again
- Never run nuclei without lowered `-rl`/`-c`
- After shallow clone of a read-only repo I may `rm -rf .git` to save space (updates = re-clone)
- Don't keep redundant wordlists

### 8.7 Cadence

One vuln category per study session (e.g. only SSRF from 4.4), then 2–3 real writeups of that class, then move on. Each session should leave a new or updated note.

---
