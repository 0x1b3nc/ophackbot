# AuthZ elite (BOLA / BFLA / GraphQL)

- **In-policy vs /force:** Object-level tests usually L2 active testing — need SCOPE `allowed` wording for authenticated testing. Cross-tenant mass enumeration may need explicit wording or `/force`.
- **Aggression:** 2 (ACTIVE). Mass ID spray = 3 / often prohibited.
- **Impact vs DoS:** Read/update another user's object = reportable. Bulk delete / lockout = PROHIBITED by default.
- **Safe lab:** DVWA / locally hosted two-tenant API before real programs.

## Theory
BOLA = broken object level; BFLA = broken function level; GraphQL batching/aliases amplify IDOR.

## Fingerprints
`/api/*/ {id}`, GraphQL `user(id:)`, invite tokens, org_id in JWT vs path.

## Scoped production checklist
1. scope_check → 2. sessions A/B → 3. workflow_run invite/IDOR dry → 4. assert_diff → 5. finding_score → log_finding.

## FP notes
Public resources, soft-deleted IDs returning 200 with empty body, identical marketing pages.
