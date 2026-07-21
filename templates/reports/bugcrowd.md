# {{TITLE}}

**VRT category:** {{VRT}}
**Target / asset:** {{TARGET}}

## Summary

Short description of the issue and why it matters. Prefer the minimal PoC below over narrative fluff.

## Preconditions

{{PRECONDITIONS}}

## Steps to reproduce (minimal PoC)

{{STEPS}}

## Observed vs expected

- Observed: response/diff differs under A vs B (or OOB hit / injection evidence)
- Expected: authorization / validation denies the cross-account or malicious input

## Impact

{{IMPACT}}

## Evidence

{{EVIDENCE}}

## Remediation

- Enforce object/role checks server-side on every write/mutation
- Add regression tests for the A/B matrix (BOLA + BFLA)
- For blinds: block egress / validate URL schemes

## Notes

- HUMAN SUBMIT GATE: review and paste into Bugcrowd; do not auto-submit
- Cookies, tokens, and session headers are redacted before share
- Severity follows program VRT; CVSS is a triage hint only
