# Mandatory Study Material Routing

Status: **mandatory workspace rule 2026-07-20**.

This file exists because the study corpus is part of the operating system for bounty work, not passive notes.

## Non-negotiable rule

Before giving conclusions, plans, scripts, report wording, severity guidance, or next-step hunting advice for a bounty task:

1. classify the task by surface and bug class
2. open `bounty_knowledge/study_notes/INDEX.md`
3. open every matching study note from the routing table below
4. apply the note checklist to the specific target/request/evidence
5. say when a conclusion is an inference instead of locally confirmed

Do not answer from memory when the class has a local study note.

## Primary routing table

| Trigger in task | Required study material |
|---|---|
| BOLA, IDOR, BAC, BFLA, access control, tenant/object boundary, role bypass, read-only bypass | `web-vulns/idor-bac.md` |
| GraphQL, resolver, mutation, batch, aliases, introspection, query complexity | `api-security/graphql-smuggling-cache.md` plus `web-vulns/idor-bac.md` for authz |
| OAuth, OIDC, JWT, session, reset password, account linking, token exchange, postMessage login | `web-vulns/auth-session.md` |
| SSRF, server-side fetch, URL import, webhook test, image/PDF fetch, cloud metadata | `web-vulns/ssrf.md` |
| SQLi, NoSQLi, command injection, SSTI, XXE, template/render, deserialization-style injection | `web-vulns/injection.md` |
| Race, async jobs, double submit, limit bypass, payment/lifecycle timing | `web-vulns/race-conditions.md` |
| DOM XSS, prototype pollution, postMessage, client-side redirect, targetOrigin, frontend sink | `web-vulns/client-side.md` |
| Request smuggling, cache poisoning, cache deception, CDN/proxy weirdness | `api-security/smuggling-cache.md` |
| API Top 10 framing, API weakness mapping, API priority planning | `api-security/owasp-api-top10.md` |
| Mobile app, MAUI/.NET, Android API, APK/JADX, cert pinning, mobile banking patterns | `api-security/mobile-maui-banking-api.md` |
| Subdomain takeover, dangling DNS, cloud bucket/app host, cname takeover | `recon/subdomain-takeover.md` |
| Content discovery, recon workflow, wordlists, archive, dorks, JS/API inventory | `recon/content-discovery.md` and any target `SCOPE.md` |
| LLM app, RAG, agent, MCP, tool-calling, prompt injection, indirect instruction, trace/report leak | `ai-security/promptfoo-lm-security-db.md` |
| Codebase/reversing/static analysis/LLM-assisted vuln detection/code review agent workflow | `ai-security/awesome-llms-vulnerability-detection.md` |
| MCP, AI confused deputy, excessive agency, AI-assisted validation | `ai-security/promptfoo-lm-security-db.md` plus `red-team/bishopfox-advisories-ai-mcp.md` |
| Cloud, identity, service accounts, IAM inheritance, data plane pivots | `red-team/bishopfox-cloud-attack-paths.md` and relevant SpecterOps notes |
| Active Directory, Entra, trusts, ADCS, delegation, SCCM | `red-team/active-directory-exploitation-cheatsheet.md` plus SpecterOps identity notes |
| MITRE/Atomic technique mapping, enterprise/lab chaining | `red-team/mitre-attack-atomic-red-team.md` and `red-team/mitre-atomic-technique-families.md` |
| Report writing, severity reasoning, prior lessons | target reports, `FINDINGS.md`, `RESUME.md`, VRT/platform policy, and local lessons |

## Target-level routing

Always read target-local material before broad study material:

1. `targets/<program>/SCOPE.md`
2. `targets/<program>/PLAN.md`
3. `targets/<program>/FINDINGS.md`
4. `targets/<program>/RESUME.md`
5. target `report/` drafts and attachments
6. target recon/raw summaries

Then read the matching study notes.

## Response discipline

When a study note has been used, the response or internal work should reflect it through concrete choices:

- endpoint classes selected from the checklist
- A/B authz matrix when relevant
- negative control planned or executed
- impact mapped to actual product behavior
- severity/weakness tied to evidence, not vibes
- no claim of "DEEP" for a paper/project unless the paper/project was opened and summarized

## Failure mode to avoid

Bad:

> "I know generally how GraphQL BOLA works, try swapping IDs."

Correct:

> Read GraphQL and IDOR notes, then test single-ID and array/batch mutations, invert ID order, verify per-object authz, and capture A/B side effects.
