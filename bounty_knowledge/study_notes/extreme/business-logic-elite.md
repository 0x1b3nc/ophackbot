# Business logic elite

- **In-policy:** Coupon/race/step-skip only if program allows ACTIVE functional testing. Payment impact tests must be zero-value / sandbox.
- **Aggression:** 2–3 (race). Financial damage / infinite credit = stop.
- **Impact vs DoS:** Redeem race = impact. Flood checkout = DoS (BLOCKED).
- **Lab:** Local cart API with coupon codes.

## Theory
State machines trust client; TOCTOU on redeem; invite reuse; price tampering in PATCH bodies.

## Fingerprints
`/redeem`, `/checkout`, `/invite/accept`, negative quantity, skipped `step=`.

## Checklist
workflow_harness multi-step → race_probe capped → cleanup mandatory.

## FP notes
Idempotent redeem returning same voucher; UI-only price fields ignored server-side.
