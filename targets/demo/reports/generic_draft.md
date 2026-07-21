# C-001 Title

**Platform draft for:** Bug bounty (platform-agnostic)  
**Type:** TBD  
**Severity hint:** TBD (confirm with program policy)  
**CVSS hint:** TBD  
**Asset / endpoint:** TBD

> Paste into Bugcrowd, HackerOne, Intigriti, YesWeHack, Synack, Immunefi, or any
> program portal. Rename sections to match that platform's submission form.
> Severity/CVSS are **triage hints** from bug class — confirm against program policy.

## Summary
C-001 Title

## Preconditions
Two in-scope test accounts A and B

## Steps to reproduce
1. Authenticate as account A and fetch owned object at TBD
2. Replay the same request as account B (ID swap only)
3. Compare responses (verdict=draft)
4. See FINDINGS.md C-001 and evidence/safe/

## Observed behavior
(see steps / evidence)

## Impact
Cross-account access to another user's object (BOLA/IDOR). Confirm data sensitivity and write paths before final severity.

## Evidence / PoC material
See evidence/safe/ and FINDINGS.md

## Remediation (suggested)
- Enforce object-level authorization on every sensitive endpoint
- Deny by default for cross-account access; return consistent 403/404
- Add regression tests for A/B ownership checks

## Notes for triage
- All testing was authorized / in-scope for this program
- Tokens and cookies are redacted in attached evidence
- Severity/CVSS above are hints derived from bug class, not final ratings
