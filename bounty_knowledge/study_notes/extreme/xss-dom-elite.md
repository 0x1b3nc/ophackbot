# XSS elite (DOM / mutation / postMessage)

- **In-policy:** Reflected/DOM XSS usually L2. CSP bypass chains OK if no malware delivery.
- **Aggression:** 2. Stored XSS in shared admin = confirm impact carefully.
- **Impact vs DoS:** Session theft / account takeover. Wormable spam = often OOS.
- **Lab:** XSS hunter / PortSwigger DOM XSS labs.

## Theory
Sinks: `innerHTML`, `eval`, `location*`, `postMessage` without origin check; mXSS; framework escapes.

## Fingerprints
`dom_xss_probe` hits; `postmessage_probe` listeners; Angular `{{constructor}}` patterns.

## Checklist
browser_map_spa → dom_xss_probe → manual confirm → screenshot redacted.

## FP notes
Self-XSS only; sinks in dead code; CSP blocks exfil.
