# Bugcrowd Notes (How I Work It)

Bugcrowd is my **default** platform (not HackerOne, unless the link says so).

## URLs and scope

- Public program: `https://bugcrowd.com/engagements/<slug>`
- Search: `https://bugcrowd.com/engagements?category=bug_bounty`
- Scope = engagement brief + targets (domains, apps, APIs, source if applicable)
- Pull scopes with my API token via [bbscope](https://github.com/sw33tLie/bbscope): `bbscope bugcrowd ...`
- Public scope dumps: [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (includes Bugcrowd)

## When I start a Bugcrowd program

1. Save policy/brief in `targets/<slug>/PROGRAM.md` or `SCOPE.md`
2. Extract in/out of scope, rewards, excluded types, required headers
3. Log the Bugcrowd slug in `WORKSPACE_STATE.md` or my private state

## Headers / identity

Some programs want a researcher header (same idea as `X-HackerOne-*`).

- Read the brief; if there's a required header, put it in `targets/<slug>/HEADERS.md`
- Send it on **every** test request when required

## Severity and report

- I rate with **Bugcrowd VRT**, not generic CVSS
- Local draft: `targets/<slug>/report/BUGCROWD_REPORT_DRAFT.md`
- Usual fields: title, VRT category, description, steps, impact, redacted PoC, remediation
- Templates: [bountyplz](https://github.com/fransr/bountyplz) (supports Bugcrowd)

## Bugcrowd vs HackerOne (what I keep in mind)

| | Bugcrowd | HackerOne |
|---|----------|-----------|
| Scope | Brief + targets on the engagement | Policy + structured scope |
| Severity | VRT | CVSS + weakness types |
| Dupes | Program disclosures | Hacktivity |
| Scope API | bbscope + BC token | H1 API / bbscope |

If someone hands me a `hackerone.com` link I treat H1 as the platform for that job.
