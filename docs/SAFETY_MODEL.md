# Safety Model

This bot is designed for authorized security work: bug bounty programs, owned
labs, CTFs, contracted pentests and education.

## Non-negotiable controls

- A target must have `SCOPE.md`.
- Out-of-scope hosts are blocked.
- Active testing must map to policy text.
- Destructive actions require explicit approval and explicit authorization.
- Secrets, cookies, tokens and PII must be redacted before reports or commits.
- Private program data belongs in `targets/<program>/`, not in the public repo.

## Aggression levels

- Level 0: passive OSINT and local analysis.
- Level 1: light active fingerprinting against confirmed in-scope assets.
- Level 2: moderate active testing such as controlled fuzzing, nuclei and A/B authz validation.
- Level 3: high-impact tests such as brute force, stress, race floods or DoS. Only allowed when the policy explicitly permits it.
