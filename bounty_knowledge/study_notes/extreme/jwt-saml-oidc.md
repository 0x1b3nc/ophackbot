# JWT / SAML / OIDC elite

- **In-policy:** Static JWT analysis L0–1. Live alg confusion / assertion tamper = lab or explicit SCOPE.
- **Aggression:** 2. Identity provider compromise attempts = OOS / prohibited.
- **Impact vs DoS:** Account takeover via token forge. Brute signing keys = stop.
- **Lab:** jwt.io + local Keycloak / SAML test IdP.

## Theory
alg none/confusion, kid/jku/x5u injection, SAML signature wrapping, OIDC mix-up, redirect_uri bypass.

## Fingerprints
`analyze_jwt`, `oidc_probe`, `saml_probe`, `oauth_probe`.

## Checklist
discovery → static checks → capped redirect_uri probe → never spam IdP.

## FP notes
RS256 advertised but HS accepted only in broken labs; staging IdPs.
