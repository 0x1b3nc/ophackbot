# Técnicas que programas proíbem (identify + stop)

- **In-policy:** Recognition only. Exploitation of DoS, social eng, physical, spam, data destruction = OUT_OF_SCOPE / BLOCKED in Hackbot.
- **Aggression:** 0 for identify. Never escalate.
- **Impact vs DoS:** N/A — stop criteria is the point.
- **Lab:** none required.

## Theory
Programs ban volumetric DoS, credential stuffing at scale, phishing, physical, destructive deletes.

## Fingerprints
Rate-limit pages, CAPTCHA storms, WAF bans — treat as stop signals.

## Checklist
1. Identify class → 2. Quote policy prohibited → 3. STOP → 4. Document in RESUME why not pursued.

## FP notes
None — this playbook exists to prevent agent overreach.
