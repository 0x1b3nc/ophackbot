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
Authorized program; in-scope host; two test accounts A/B when authz

## Steps to reproduce
## Minimal PoC (tbd)
1. Target: `TBD`
2. Method(s): `GET`  matrix=`bola`
3. Send the proving request (see evidence JSON winning_replay).
4. Compare against negative control (unauthenticated / benign input).
5. Capture response diff that demonstrates impact.
6. Finding id `C-001` verdict=`draft` — attach redacted evidence.

## Observed behavior
(see steps / evidence)

## Impact
Potential TBD on TBD. Confirm data sensitivity and write/mutation impact before final severity.

VRT hint: TBD

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
