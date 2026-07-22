# SSRF elite

- **In-policy:** http(s) canaries usually L2. Cloud metadata / file/gopher need SCOPE L3 or `/force`.
- **Aggression:** 2 default; protocol matrix exotic = 3.
- **Impact vs DoS:** Metadata read / internal pivot. Port-scan floods = DoS (BLOCKED).
- **Lab:** SSRF labs with metadata mock.

## Theory
Filter bypass, DNS rebinding, blind OOB, protocol smuggling into parsers.

## Fingerprints
URL params `url=`, `webhook=`, PDF renderers, image fetchers.

## Checklist
ssrf_probe → ssrf_protocol_matrix (http/s only) → oob_poll → stop before internal brute.

## FP notes
Open redirects mistaken for SSRF; DNS to attacker without fetch.
