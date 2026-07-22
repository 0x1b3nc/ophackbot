# Cache poison / web cache deception

- **In-policy:** Unkeyed header / path suffix tests usually L2 if low rate.
- **Aggression:** 2. Cache flush / ban evasion = stop.
- **Impact vs DoS:** Poisoned private response to others. Mass PURGE = DoS (BLOCKED).
- **Lab:** Local Varnish/nginx cache.

## Theory
FAT GET, path `/account` + `/static.css`, unkeyed `X-Forwarded-Host`.

## Fingerprints
`cache_poison_probe` findings; Age/Cache-Control on dynamic paths.

## Checklist
dry-run → single canary → evidence → no mass poison.

## FP notes
Personalized `Vary: Cookie` already correct; CDN ignores XFH.
