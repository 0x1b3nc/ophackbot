# How I Keep This Safe

I built this for authorized work only: bug bounty, my own labs, CTFs, contracted
pentests, and learning. I don't point it at systems without permission.

## Non-negotiable for me

- Every target needs a `SCOPE.md`
- Out-of-scope hosts get blocked
- Active testing has to map to policy text
- Destructive stuff needs explicit approval and explicit authorization
- Secrets, cookies, tokens, and PII get redacted before reports or commits
- Regex redact is best effort. For a harder gate set `HACKBOT_STRICT_REDACT=1`
  so evidence/reports refuse to save if unknown headers still have values after
  redact (or if it still looks sensitive)
- Private program junk stays under `targets/<program>/`, not in the public repo
- Every allow/deny on file changes and active traffic appends to `audit.log`
  (gitignored) so I can reconstruct what I approved later

## Aggression levels I use

- Level 0: passive OSINT and local analysis
- Level 1: light active fingerprinting on confirmed in-scope assets
- Level 2: moderate active work (controlled fuzz, nuclei, A/B authz)
- Level 3: high-impact (brute, stress, race floods, DoS). Only when the policy
  explicitly says I can
