# Request smuggling / desync (DETECTION ONLY)

- **In-policy:** Detection differentials often need L3 wording. Volume DoS ALWAYS prohibited.
- **Aggression:** 3. Hackbot `http_smuggle_probe` is detection-only.
- **Impact vs DoS:** Demonstrable request hijack in lab. Bandwidth/CPU exhaustion = BLOCKED.
- **Lab:** PortSwigger HTTP/1.1 desync labs offline.

## Theory
CL.TE / TE.CL parser disagreement; never send attack bodies at scale on BB targets.

## Fingerprints
`http_smuggle_probe` hints (Via, TE support). Confirm only in lab.

## Checklist
identify → screenshot headers → STOP. No exploit chain on production.

## FP notes
CDN normalizing TE; false timing noise.
