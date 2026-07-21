# {{TITLE}}

**Platform draft for:** {{PLATFORM}}  
**Type:** {{VULN_TYPE}}  
**Severity hint:** {{SEVERITY}}  
**CVSS hint:** {{CVSS}}  
**Asset / endpoint:** {{TARGET}}

> Paste into Bugcrowd, HackerOne, Intigriti, YesWeHack, Synack, Immunefi, or any
> program portal. Rename sections to match that platform's submission form.
> Severity/CVSS are **triage hints** from bug class. Confirm against program policy.

## Summary
{{TITLE}}

## Preconditions
{{PRECONDITIONS}}

## Steps to reproduce
{{STEPS}}

## Observed behavior
{{OBSERVED}}

## Impact
{{IMPACT}}

## Evidence / PoC material
{{EVIDENCE}}

## Remediation (suggested)
- Enforce object-level authorization on every sensitive endpoint
- Deny by default for cross-account access; return consistent 403/404
- Add regression tests for A/B ownership checks

## Notes for triage
- All testing was authorized / in-scope for this program
- Tokens and cookies are redacted in attached evidence
- Severity/CVSS above are hints derived from bug class, not final ratings
