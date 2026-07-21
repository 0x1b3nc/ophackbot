# How I Keep This Safe

I built this for authorized work only: bug bounty, my own labs, CTFs, contracted
pentests, and learning. I don't point it at systems without permission.

## Non-negotiable for me

- Every target needs a `SCOPE.md`
- Explicitly **OUT_OF_SCOPE** hosts stay hard-blocked (even with `/force`)
- Active testing should map to policy text by default
- Destructive / level-3 work needs explicit SCOPE wording **or** a conscious
  `/force` override — then **approve** — then execute
- Secrets, cookies, tokens, and PII get redacted before reports or commits
- Regex redact is best effort. For a harder gate set `HACKBOT_STRICT_REDACT=1`
  so evidence/reports refuse to save if unknown headers still have values after
  redact (or if it still looks sensitive)
- Private program junk stays under `targets/<program>/`, not in the public repo
- Every allow/deny on file changes and active traffic appends to `audit.log`
  (gitignored), including `force_override=True` when I used `/force`

## Secrets / sessions

- Live tokens and cookies go in `targets/<program>/secrets/sessions.yaml`
- That path is gitignored. Only `sessions.example.yaml` is safe to commit
- UI and audit logs show **masked** values only
- Required program headers: SCOPE YAML `headers:` and/or `sessions.yaml` `headers:`

## Operator model

```text
SCOPE (default gates)  →  /force (soft override, my responsibility)
                       →  approve (Confirm before live traffic)
                       →  execute
```

`/force` does **not** skip approve. It does **not** unlock hosts marked
OUT_OF_SCOPE. It only overrides soft gates: level-3 / active-testing wording
missing from SCOPE, and hosts still `NOT_CONFIRMED`.

HTTP redirects and derived fetches (HAR/OpenAPI/surface) re-gate each
**effective destination**. An in-scope hop that lands on an OOS host is
hard-blocked without force; intentional `/force` for soft-gated destinations
stays operator responsibility.

### Session approve (`/hunt --approve`)

Autonomous hunt uses **one session approve** for the whole OODA loop instead of
per-tool confirms. That still does **not** bypass SCOPE or OOS. Each act is
audited (`hunt_start` / tool allows). Caps remain (brute ≤ 20, rate_probe
bounded, sqli/xss tiny probe sets). Validator must reproduce proof before
`FINDINGS.md`.

## Aggression levels I use

- Level 0: passive OSINT and local analysis
- Level 1: light active fingerprinting on confirmed in-scope assets
- Level 2: moderate active work (controlled fuzz, nuclei, A/B authz, sqli/xss probes)
- Level 3: high-impact (bounded rate-limit / concurrency probes, brute, stress).
  Default: only when SCOPE Explicitly Allowed mentions it. Override: `/force`
  (audited). The kit's `rate_probe` tool is **capped** (concurrency ≤ 20,
  total ≤ 100) — not an unbounded flood.
