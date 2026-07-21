# Prompt I Hand to Other Agents

You're helping me evolve this into my authorized Hackbot bounty kit.
Here's how I work. Match it.

## Context

This is my agent/CLI for authorized security research: bug bounty, CTF, labs I
own, contracted pentests, and learning. I want strong analysis, good hypothesis
selection, and controlled automation. I never point this at targets without auth.

## Main rule

Before any plan, command, script, report, severity, or next step:

1. Read `docs/OPERATING_RULES.md`
2. Read `bounty_knowledge/study_notes/INDEX.md`
3. Read `bounty_knowledge/study_notes/STUDY_MATERIAL_ROUTING.md`
4. Classify the task by surface and bug class
5. Open the matching class notes
6. Read `targets/<program>/SCOPE.md`, `PLAN.md`, `FINDINGS.md`, `RESUME.md`
7. If it isn't confirmed locally, call it inference

## What I want built

Keep evolving this repo with:

- CLI `hackbot`
- scope guard
- policy/scope parsing
- evidence manager with redaction
- integrations for HexStrike, reconFTW, Burp exports, nuclei, httpx, katana, ffuf
- knowledge router
- hypothesis planner
- Bugcrowd / HackerOne / Intigriti report templates
- automated tests
- clear Windows/Linux docs

## Layout I want

```text
hackbot/
  cli.py
  policy_guard.py
  planner.py
  knowledge.py
  evidence.py
  redaction.py
  runners/
    hexstrike.py
    reconftw.py
    burp.py
    projectdiscovery.py
  reporting/
    bugcrowd.py
    hackerone.py
    intigriti.py
configs/
docs/
templates/
targets/
```

## How I operate

I don't move without:

- falsifiable hypothesis
- target/endpoint
- preconditions
- aggression level 0-3
- policy quote that authorizes the action
- concrete command or script
- expected evidence
- stop criteria
- cleanup

## Don't put this in the public repo

- private programs
- cookies
- tokens
- session headers
- HAR/Burp XML with real session
- screenshots with PII
- private reports
- recon dumps of real companies
- giant wordlists or third-party corpora without checking license

## Tech priorities

1. `python -m hackbot target-init demo`
2. `python -m hackbot scope-check targets/demo --host example.com`
3. Tests for `policy_guard.py`
4. `hackbot/knowledge.py` opens mandatory notes by class
5. `hackbot/redaction.py` strips `Authorization`, `Cookie`, tokens, emails, secrets
6. Runners print commands first and only execute with `--approve`
7. All active behavior stays tied to scope

## Tone

Pragmatic, direct, technical. No hype in the README. Value comes from scope,
evidence, controlled automation, and reproducible reports. Write docs like I'm
explaining my own kit to another hunter, first person, informal English.
