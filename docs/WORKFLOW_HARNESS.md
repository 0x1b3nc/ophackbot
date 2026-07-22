# Workflow harness

Target-local multi-step business-logic / authz scenarios.

## Layout

```
targets/<name>/hunt/workflows/<id>.yaml
targets/<name>/hunt/workflows/_state/<id>.json   # runtime vars + results
targets/<name>/hunt/coverage.yaml                 # class×endpoint coverage
```

## Tools

| Tool | Traffic | Role |
|------|---------|------|
| `workflow_load` | none | list / parse / preview |
| `workflow_run` | dry-run default; ACTIVE with `approve=true` | execute steps |
| `workflow_assert` | none | re-check asserts vs cached labels / state |
| `coverage_map` | none | read / mark / summary |

## Step kinds

- `request` — wraps `http_request` (SCOPE + approve rails)
- `extract` — jsonpath / regex from labeled response → `vars`
- `mutate` — set vars (no traffic)
- `assert` — status / regex / jsonpath / `diff_labels` (via `assert_diff`)
- `tool` — any registered tool (nested approve already granted for ACTIVE run)

## Gates

- Default `approve=false` → dry-run plan only (marks coverage `dry`)
- `approve=true` → one operator confirm for the whole workflow; nested steps auto-allow
- Every request URL passes `ScopePolicy.assert_action_allowed` (OUT_OF_SCOPE never bypassed)
- `cleanup` steps run after ACTIVE execution (best-effort)
- Accounts A/B/C = `session` labels from `secrets/sessions.yaml`

## Playbooks vs workflows

- **Playbooks** (`open_playbook` / `run_playbook`) — class templates in Python
- **Workflows** — target-specific YAML with extract/mutate state

See template: `templates/target/hunt/workflows/idor_invite_accept.yaml`
