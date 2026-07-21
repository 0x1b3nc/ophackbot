# Workspace State

Use this file for public/demo state only.

Private program state, accounts, report status, session notes and target-specific
evidence should stay in a private workspace or in `targets/<program>/` files that
are not committed to a public repository.

## Public kit status (2026-07-20)

- CLI package scaffold complete: policy guard, knowledge router, planner,
  evidence/redaction, runners (print-first / `--approve`), report drafts.
- Demo target: `targets/demo` with template scope (`example.com`).
- Tests: `python -m unittest discover -s tests -v`
