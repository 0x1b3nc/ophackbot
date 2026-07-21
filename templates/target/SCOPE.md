---
in_scope:
  - example.com
out_of_scope:
  - "*.example.net"
allowed:
  - Passive recon
prohibited:
  - DoS
  - Brute force
  - Credential stuffing
  - Spam
  - Destructive actions
---

# Scope

I paste the official program scope and policy here. The YAML block above is the
source of truth for hosts and allowed/prohibited actions. Markdown below is for
my notes.

## Required Headers / Identity

- None documented yet.

## Rate Limits / Automation

- Not confirmed yet. I treat active scanning as off-limits until the policy says otherwise.
