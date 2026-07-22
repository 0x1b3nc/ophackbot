# Race / TOCTOU elite

- **In-policy:** Capped race on redeem/limits if ACTIVE allowed. Unlimited parallel = DoS.
- **Aggression:** 3 (`race_probe` workers capped).
- **Impact vs DoS:** Limit overrun / dual redeem. Service outage = BLOCKED.
- **Lab:** Local coupon service with atomicity bug.

## Theory
TOCTOU between check and debit; dual-use invite tokens; parallel PATCH.

## Fingerprints
`race_probe` status variance; workflow redeem steps.

## Checklist
workflow dry → race_probe approve → cleanup → finding_score.

## FP notes
Eventually consistent 200s without extra credit; CDN retries.
