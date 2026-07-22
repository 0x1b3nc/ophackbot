# Attack chaining for bug bounty impact

- **In-policy:** Chains only with validated asserts per hop. No pivot outside SCOPE.
- **Aggression:** max of hops (usually 2).
- **Impact vs DoS:** Chained ATO / data access. Internal scanning after SSRF = careful / often OOS.
- **Lab:** Multi-vuln local apps.

## Theory
recon → authz → SSRF → limited pivot; document each hop with evidence.

## Fingerprints
`build_chains` + `chain_validate` with label asserts.

## Checklist
assert each edge → chain_validate → only then FINDINGS / report draft.

## FP notes
Speculative chains without evidence; out-of-scope hops.
