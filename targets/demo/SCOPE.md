---
in_scope:
  - example.com
  - demo.hackbot.local
out_of_scope:
  - "*.example.net"
allowed:
  - Passive recon
  - Active testing
  - IDOR / BOLA checks with provided test accounts
  - Controlled race condition testing
  - Rate-limit testing
prohibited:
  - DoS
  - Credential stuffing against third parties
  - Destructive actions
---

# Scope

Demo program for smoke-testing the kit. Not a real bounty.

Use `example.com` / `demo.hackbot.local` for dry-runs. Fake sessions live in
`secrets/sessions.yaml` (gitignored). Copy from `sessions.example.yaml`.

## Required Headers / Identity

- Bug bounty header optional: `X-Bug-Bounty: hackbot-demo`

## Rate Limits / Automation

- Keep probes capped (kit defaults). Active traffic still needs `approve`.
