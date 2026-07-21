# My Knowledge Base

I only ship my own reusable notes and write-ups in this kit. Big third-party
corpora stay as local knowledge deps. I don't version them in the public repo.

## What's in here

- `study_notes/`: per-bug-class notes + mandatory routing
- `BUGBOUNTY_STUDY_GUIDE.md`: how I study web/bounty
- `BUGCROWD.md`: how I run Bugcrowd programs
- `TOOLCHAIN.md`: tools I use per phase
- `LESSONS_MOBILE_API_AUTH.md`: patterns I reuse on mobile/API/auth
- `techniques/`: short personal techniques and checklists

## Sources I import outside Git

When I want the big corpora locally I run `scripts/import_knowledge_sources.sh`:

- OWASP WSTG
- OWASP API Security
- OWASP ASVS
- OWASP MASTG
- OWASP Cheat Sheet Series
- PayloadsAllTheThings
- SecLists
- nuclei-templates
- Bugcrowd University
- Vulnerability Rating Taxonomy
- The Bug Hunter's Methodology
- CloudGoat
- ClaudeBrain

Those have their own licenses and sizes. I keep them in `external_knowledge/`,
outside the public package, or I document licenses if I ever vendor one.

## How I use this

Before plan, script, report, severity, or next hunting step I read:

1. `docs/OPERATING_RULES.md`
2. `bounty_knowledge/study_notes/INDEX.md`
3. `bounty_knowledge/study_notes/STUDY_MATERIAL_ROUTING.md`
4. The notes for that bug class
5. The target's `SCOPE.md`

I think aggressively about coverage. I stay conservative on active traffic when
the policy doesn't clearly allow heavy scanning, brute, DoS, stress, spam, or
destructive actions.
