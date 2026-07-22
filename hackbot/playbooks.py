"""Class playbooks: knowledge routed into falsifiable (and optionally executable) steps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .knowledge import classify, notes_for_classes


@dataclass(frozen=True)
class PlaybookStep:
    title: str
    hypothesis: str
    aggression: int
    command: str
    expected: str
    stop: str
    tool_call: dict[str, Any] | None = None


@dataclass(frozen=True)
class Playbook:
    class_name: str
    summary: str
    preconditions: tuple[str, ...]
    steps: tuple[PlaybookStep, ...]
    study_notes: tuple[str, ...]


_PLAYBOOKS: dict[str, Playbook] = {
    "idor": Playbook(
        class_name="idor",
        summary="Object-level authz: swap an owned ID while authenticated as another user.",
        preconditions=(
            "Two owned test accounts A and B",
            "Capture a private object ID belonging to A from normal traffic",
            "Host confirmed in SCOPE.md",
        ),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="The host is listed in SCOPE.md before any traffic.",
                aggression=0,
                command="hackbot: scope_check on {target_dir} --host {host}",
                expected="IN_SCOPE status.",
                stop="NOT_CONFIRMED or OUT_OF_SCOPE.",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "idor authz swap",
                    },
                },
            ),
            PlaybookStep(
                title="Baseline as owner",
                hypothesis="Owner A can read their own object at the candidate endpoint.",
                aggression=1,
                command="http_request GET {endpoint} session=A",
                expected="200 with A-owned fields.",
                stop="Auth fails, 404 for owner, or endpoint not confirmed. Load secrets/sessions.yaml first.",
                tool_call={
                    "tool": "http_request",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "method": "GET",
                        "session": "A",
                        "label": "idor_A",
                    },
                },
            ),
            PlaybookStep(
                title="Cross-account swap",
                hypothesis="User B can read A's object by swapping only the object ID.",
                aggression=2,
                command="http_request GET {endpoint} session=B  # same URL as A's object",
                expected="Secure: 403/404. Vulnerable: 200 with A's private data.",
                stop="Any unexpected write, rate-limit, or out-of-scope host.",
                tool_call={
                    "tool": "http_request",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "method": "GET",
                        "session": "B",
                        "label": "idor_B",
                    },
                },
            ),
            PlaybookStep(
                title="Diff A vs B",
                hypothesis="Cross-account response proves or falsifies object-level authz.",
                aggression=2,
                command="assert_diff label_a=idor_A label_b=idor_B",
                expected="negative (denied) or confirmed/likely (IDOR).",
                stop="inconclusive — fix sessions/baseline.",
                tool_call={
                    "tool": "assert_diff",
                    "args": {
                        "target_dir": "{target_dir}",
                        "label_a": "idor_A",
                        "label_b": "idor_B",
                        "kind": "idor",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["idor"])),
    ),
    "ssrf": Playbook(
        class_name="ssrf",
        summary="Server-side fetch of attacker-controlled URLs / metadata endpoints.",
        preconditions=(
            "In-scope parameter that accepts a URL or host",
            "Out-of-band or local callback you control (or metadata IP if policy allows)",
        ),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="The host is listed in SCOPE.md before any traffic.",
                aggression=0,
                command="hackbot: scope_check on {target_dir} --host {host}",
                expected="IN_SCOPE status.",
                stop="NOT_CONFIRMED or OUT_OF_SCOPE.",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "ssrf probe",
                    },
                },
            ),
            PlaybookStep(
                title="Benign fetch",
                hypothesis="The app fetches the URL I supply and returns or logs the response.",
                aggression=1,
                command='http_request POST {endpoint} body={"url":"https://example.com/"} session=A',
                expected="Response/log shows fetched content or error from remote.",
                stop="No fetch behavior; parameter ignored. Adjust body key to match the param.",
                tool_call={
                    "tool": "http_request",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "method": "POST",
                        "session": "A",
                        "body": '{"url":"https://example.com/"}',
                        "content_type": "application/json",
                        "label": "ssrf_benign",
                    },
                },
            ),
            PlaybookStep(
                title="Internal probe (policy permitting)",
                hypothesis="The server can reach link-local/metadata or internal hosts.",
                aggression=2,
                command='http_request POST {endpoint} body={"url":"http://127.0.0.1/"}',
                expected="Internal banner/body vs external control proves SSRF.",
                stop="Cloud metadata / level-3 prohibited by SCOPE; stop immediately.",
                tool_call={
                    "tool": "http_request",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "method": "POST",
                        "session": "A",
                        "body": '{"url":"http://127.0.0.1/"}',
                        "content_type": "application/json",
                        "label": "ssrf_internal",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["ssrf"])),
    ),
    "xss": Playbook(
        class_name="xss",
        summary="Script sinks: reflected/stored input reaches HTML/JS without encoding.",
        preconditions=("In-scope input that echoes into HTML/JS", "Browser or proxy to observe sink"),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Endpoint is in SCOPE before any reflection probe.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE / allowed for reflection testing.",
                stop="OUT_OF_SCOPE or NOT_CONFIRMED without /force.",
                tool_call={
                    "tool": "scope_check",
                    "args": {"target_dir": "{target_dir}", "host": "{host}"},
                },
            ),
            PlaybookStep(
                title="Canary reflect",
                hypothesis="My marker string is reflected into the response body unencoded.",
                aggression=1,
                command='xss_probe "$ENDPOINT" param=q',
                expected="Marker appears in HTML/JS context.",
                stop="No reflection.",
                tool_call={
                    "tool": "xss_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "param": "q",
                        "approve": "{approve}",
                        "force": "{force}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["xss"])),
    ),
    "sqli": Playbook(
        class_name="sqli",
        summary="Injection into queries: boolean/time differentials with tight stop criteria.",
        preconditions=("In-scope parameter suspected in a query", "Low rate; no destructive payloads"),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Endpoint is in SCOPE before injection probes.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE.",
                stop="OUT_OF_SCOPE.",
                tool_call={
                    "tool": "scope_check",
                    "args": {"target_dir": "{target_dir}", "host": "{host}"},
                },
            ),
            PlaybookStep(
                title="Boolean / error differential",
                hypothesis="True/false or syntax probes change status/body in a query-dependent way.",
                aggression=2,
                command='sqli_probe "$ENDPOINT" param=id',
                expected="Clear differential or SQL error marker; not just WAF noise.",
                stop="WAF 403 loop, errors without differential, or SCOPE forbids injection tests.",
                tool_call={
                    "tool": "sqli_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "param": "id",
                        "approve": "{approve}",
                        "force": "{force}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["sqli"])),
    ),
    "race": Playbook(
        class_name="race",
        summary="TOCTOU / limit bypass with parallel requests against the same resource.",
        preconditions=("Two parallel slots or scripted concurrent requests", "Idempotent or reversible action"),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="The host is listed in SCOPE.md before any traffic.",
                aggression=0,
                command="hackbot: scope_check on {target_dir} --host {host}",
                expected="IN_SCOPE status.",
                stop="NOT_CONFIRMED or OUT_OF_SCOPE.",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "race parallel burst",
                    },
                },
            ),
            PlaybookStep(
                title="Single-thread limit",
                hypothesis="The limit/coupon/balance enforces correctly for one request at a time.",
                aggression=1,
                command='curl -i -X POST "$ENDPOINT" -H "Cookie: SESSION=A" -d "..."',
                expected="Limit holds for sequential calls.",
                stop="Action not reversible; abort.",
            ),
            PlaybookStep(
                title="Parallel burst (bounded)",
                hypothesis="N concurrent requests bypass the limit once.",
                aggression=2,
                command="rate_probe concurrency=5 total=10 against $ENDPOINT",
                expected="More successes than the limit allows.",
                stop="One burst only; clean up created objects; no unbounded flood.",
                tool_call={
                    "tool": "run_tool",
                    "args": {
                        "target_dir": "{target_dir}",
                        "tool": "rate_probe",
                        "host": "{endpoint}",
                        "concurrency": 5,
                        "total": 10,
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["race"])),
    ),
    "recon": Playbook(
        class_name="recon",
        summary="Passive-first recon then light fingerprint on confirmed in-scope hosts.",
        preconditions=("SCOPE.md filled", "No active scanning until policy allows"),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="The host is listed in SCOPE.md before any traffic.",
                aggression=0,
                command="hackbot: scope_check on {target_dir} --host {host}",
                expected="IN_SCOPE status.",
                stop="NOT_CONFIRMED or OUT_OF_SCOPE.",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "httpx fingerprint",
                    },
                },
            ),
            PlaybookStep(
                title="Passive notes",
                hypothesis="Public sources yield candidate hosts/endpoints without touching the target.",
                aggression=0,
                command="# crt.sh / wayback / program assets — record under evidence/safe/",
                expected="Short list of candidates with sources.",
                stop="No candidates; refine program assets.",
            ),
            PlaybookStep(
                title="Light fingerprint (if allowed)",
                hypothesis="httpx confirms live HTTP on an in-scope host.",
                aggression=1,
                command="run_tool httpx (approve=false first)",
                expected="Status/title/tech without heavy crawling.",
                stop="Active scanning not in SCOPE allowed list.",
                tool_call={
                    "tool": "run_tool",
                    "args": {
                        "target_dir": "{target_dir}",
                        "tool": "httpx",
                        "host": "{host}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["recon"])),
    ),
    "rate-limit": Playbook(
        class_name="rate-limit",
        summary=(
            "Controlled concurrency probe to test rate limits / soft DoS posture. "
            "Hard-capped totals — not an unbounded flood. Needs SCOPE level-3 wording or /force."
        ),
        preconditions=(
            "Host in SCOPE.md (or operator /force for NOT_CONFIRMED)",
            "Level-3 allowed in SCOPE or /force with operator responsibility",
            "Prefer a durable, non-destructive endpoint",
        ),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Policy allows (or force overrides) a bounded rate-limit probe.",
                aggression=0,
                command="hackbot: scope_check --action 'rate-limit testing'",
                expected="IN_SCOPE; level 3 allowed or force planned.",
                stop="OUT_OF_SCOPE host.",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "rate-limit testing dos stress",
                    },
                },
            ),
            PlaybookStep(
                title="Baseline single request",
                hypothesis="A single GET returns a stable status for the endpoint.",
                aggression=1,
                command="run_tool httpx against {host}",
                expected="Live HTTP status/title.",
                stop="Host down or TLS failure.",
                tool_call={
                    "tool": "run_tool",
                    "args": {
                        "target_dir": "{target_dir}",
                        "tool": "httpx",
                        "host": "{host}",
                    },
                },
            ),
            PlaybookStep(
                title="Bounded concurrency probe",
                hypothesis="Status/latency under capped parallel load reveals rate-limit behavior.",
                aggression=3,
                command="rate_probe concurrency=5 total=25 timeout=5s",
                expected="Status histogram + avg latency; 429/503 or soft degradation is evidence.",
                stop="Stop after one bounded run; do not raise caps without re-reading SCOPE.",
                tool_call={
                    "tool": "run_tool",
                    "args": {
                        "target_dir": "{target_dir}",
                        "tool": "rate_probe",
                        "host": "{endpoint}",
                        "concurrency": 5,
                        "total": 25,
                        "timeout": 5.0,
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["race", "api"])),
    ),
    "brute": Playbook(
        class_name="brute",
        summary=(
            "Capped password spray against a login endpoint (max 20 attempts). "
            "Requires SCOPE level-3 wording or /force."
        ),
        preconditions=(
            "Login URL (default /login)",
            "Level-3 allowed or /force",
            "Prefer program test accounts only",
        ),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Brute/spray is allowed for this host.",
                aggression=0,
                command="scope_check action=brute force",
                expected="IN_SCOPE; level 3 or force.",
                stop="OUT_OF_SCOPE",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "brute force password spray",
                    },
                },
            ),
            PlaybookStep(
                title="Capped spray",
                hypothesis="A weak password on the test user is accepted.",
                aggression=3,
                command="brute_login {endpoint} username=test",
                expected="success=false (secure) or success=true (finding).",
                stop="Lockout / CAPTCHA — stop immediately.",
                tool_call={
                    "tool": "brute_login",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "username": "test",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["brute"])),
    ),
    "auth-bypass": Playbook(
        class_name="auth-bypass",
        summary=(
            "Login / password bypass probes: empty password, SQL-ish auth payloads, "
            "verb tampering. Tight stop — not credential stuffing."
        ),
        preconditions=(
            "Login endpoint known (default /login or prompt path)",
            "Host in SCOPE; prefer test account usernames only",
        ),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Login host is in SCOPE before auth probes.",
                aggression=0,
                command="scope_check {host} action=auth bypass",
                expected="IN_SCOPE",
                stop="OUT_OF_SCOPE",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "auth bypass login",
                    },
                },
            ),
            PlaybookStep(
                title="Empty password",
                hypothesis="Empty password is accepted for a known username.",
                aggression=2,
                command='http_request POST {endpoint} body=username=test&password=',
                expected="Secure: 401/403. Vuln: 200/302 into session.",
                stop="Account lockout signals — abort.",
                tool_call={
                    "tool": "http_request",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "method": "POST",
                        "body": "username=test&password=",
                        "content_type": "application/x-www-form-urlencoded",
                        "label": "bypass_empty",
                    },
                },
            ),
            PlaybookStep(
                title="SQLi auth probe (single)",
                hypothesis="Classic auth SQLi payload alters login outcome.",
                aggression=2,
                command="http_request POST login with ' OR '1'='1",
                expected="Secure: fail. Vuln: unexpected success / error differential.",
                stop="One probe only; no dump payloads.",
                tool_call={
                    "tool": "http_request",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "method": "POST",
                        "body": "username=admin' OR '1'='1&password=x",
                        "content_type": "application/x-www-form-urlencoded",
                        "label": "bypass_sqli",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["brute", "jwt", "session"])),
    ),
    "secrets": Playbook(
        class_name="secrets",
        summary="Scan common paths and responses for exposed tokens / credentials.",
        preconditions=("Host in SCOPE",),
        steps=(
            PlaybookStep(
                title="Secrets scan",
                hypothesis="Config/env/JS endpoints leak credentials or tokens.",
                aggression=1,
                command="secrets_scan {host}",
                expected="No secrets, or redacted hits with kind+URL.",
                stop="Stop after one pass; confirm impact manually.",
                tool_call={
                    "tool": "secrets_scan",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["api", "recon"])),
    ),
    "lfi": Playbook(
        class_name="lfi",
        summary="Path traversal / local file inclusion via file-like params.",
        preconditions=("In-scope param that reads files",),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Host in SCOPE.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OOS",
                tool_call={"tool": "scope_check", "args": {"target_dir": "{target_dir}", "host": "{host}"}},
            ),
            PlaybookStep(
                title="Traversal canary",
                hypothesis="../../etc/passwd or win.ini markers appear.",
                aggression=2,
                command="lfi_probe",
                expected="File marker in body.",
                stop="No marker / WAF loop.",
                tool_call={
                    "tool": "lfi_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "param": "file",
                        "approve": "{approve}",
                        "force": "{force}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["injection", "lfi"])),
    ),
    "ssti": Playbook(
        class_name="ssti",
        summary="Server-side template injection via math canaries.",
        preconditions=("Reflected param into template engine",),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Host in SCOPE.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OOS",
                tool_call={"tool": "scope_check", "args": {"target_dir": "{target_dir}", "host": "{host}"}},
            ),
            PlaybookStep(
                title="Math canary",
                hypothesis="{{7*7}} evaluates to 49.",
                aggression=2,
                command="ssti_probe",
                expected="Evaluated canary.",
                stop="No evaluation.",
                tool_call={
                    "tool": "ssti_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "param": "q",
                        "approve": "{approve}",
                        "force": "{force}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["ssti", "injection"])),
    ),
    "xxe": Playbook(
        class_name="xxe",
        summary="XML external entity file-read probe.",
        preconditions=("XML-accepting endpoint",),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Host in SCOPE.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OOS",
                tool_call={"tool": "scope_check", "args": {"target_dir": "{target_dir}", "host": "{host}"}},
            ),
            PlaybookStep(
                title="XXE file canary",
                hypothesis="file:///etc/passwd content reflected.",
                aggression=2,
                command="xxe_probe",
                expected="passwd/win.ini markers.",
                stop="Parser disables external entities.",
                tool_call={
                    "tool": "xxe_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": "{approve}",
                        "force": "{force}",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["xxe", "injection"])),
    ),
    "invite-idor": Playbook(
        class_name="invite-idor",
        summary="Multi-step invite accept / cross-account IDOR via workflow harness.",
        preconditions=("Accounts A/B", "workflow YAML or invite endpoints", "SCOPE IN"),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Host in SCOPE before invite traffic.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OOS",
                tool_call={
                    "tool": "scope_check",
                    "args": {"target_dir": "{target_dir}", "host": "{host}"},
                },
            ),
            PlaybookStep(
                title="Load invite workflow",
                hypothesis="Target has hunt/workflows/idor_invite_accept.yaml",
                aggression=0,
                command="workflow_load",
                expected="steps preview",
                stop="missing workflow — copy template",
                tool_call={
                    "tool": "workflow_load",
                    "args": {
                        "target_dir": "{target_dir}",
                        "workflow_id": "idor_invite_accept",
                    },
                },
            ),
            PlaybookStep(
                title="Dry-run workflow",
                hypothesis="Plan request/extract/assert without ACTIVE traffic.",
                aggression=1,
                command="workflow_run approve=false",
                expected="dry-run plan + coverage dry marks",
                stop="OOS in plan URLs",
                tool_call={
                    "tool": "workflow_run",
                    "args": {
                        "target_dir": "{target_dir}",
                        "workflow_id": "idor_invite_accept",
                        "approve": False,
                    },
                },
            ),
            PlaybookStep(
                title="ACTIVE workflow",
                hypothesis="A creates invite; B accepts; assert proves authz gap.",
                aggression=2,
                command="workflow_run approve=true",
                expected="assert results + cleanup",
                stop="assert_fail or scope_denied",
                tool_call={
                    "tool": "workflow_run",
                    "args": {
                        "target_dir": "{target_dir}",
                        "workflow_id": "idor_invite_accept",
                        "approve": True,
                    },
                },
            ),
        ),
        study_notes=("extreme/authz-elite.md", "extreme/business-logic-elite.md"),
    ),
    "dom-xss": Playbook(
        class_name="dom-xss",
        summary="DOM sink inventory then capped confirmation.",
        preconditions=("Playwright available", "IN_SCOPE URL"),
        steps=(
            PlaybookStep(
                title="Scope",
                hypothesis="Host in SCOPE.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OOS",
                tool_call={
                    "tool": "scope_check",
                    "args": {"target_dir": "{target_dir}", "host": "{host}"},
                },
            ),
            PlaybookStep(
                title="DOM sink scan",
                hypothesis="Page sources contain dangerous sinks.",
                aggression=2,
                command="dom_xss_probe",
                expected="hits list; signal if assign sinks",
                stop="no sinks → stop",
                tool_call={
                    "tool": "dom_xss_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": "{approve}",
                    },
                },
            ),
            PlaybookStep(
                title="postMessage inventory",
                hypothesis="message listeners without origin checks.",
                aggression=2,
                command="postmessage_probe",
                expected="listener fingerprint",
                stop="none",
                tool_call={
                    "tool": "postmessage_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": "{approve}",
                    },
                },
            ),
        ),
        study_notes=("extreme/xss-dom-elite.md",),
    ),
    "cache-detect": Playbook(
        class_name="cache-detect",
        summary="Web cache deception / unkeyed header detection (safe, capped).",
        preconditions=("IN_SCOPE URL", "no mass poison"),
        steps=(
            PlaybookStep(
                title="Scope",
                hypothesis="Host in SCOPE.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OOS",
                tool_call={
                    "tool": "scope_check",
                    "args": {"target_dir": "{target_dir}", "host": "{host}"},
                },
            ),
            PlaybookStep(
                title="Cache poison probe",
                hypothesis="Path suffix or XFH reflection indicates cache risk.",
                aggression=2,
                command="cache_poison_probe",
                expected="findings or neg",
                stop="WAF ban / rate limit",
                tool_call={
                    "tool": "cache_poison_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": "{approve}",
                    },
                },
            ),
        ),
        study_notes=("extreme/cache-poison-deception.md",),
    ),
    "prohibited-stop": Playbook(
        class_name="prohibited-stop",
        summary="Identify techniques programs forbid; document and STOP (no exploit).",
        preconditions=("Read SCOPE prohibited section",),
        steps=(
            PlaybookStep(
                title="Open prohibited note",
                hypothesis="Agent must not escalate DoS/social/destructive paths.",
                aggression=0,
                command="open_knowledge prohibited",
                expected="identify+stop guidance",
                stop="always stop after identify",
                tool_call={
                    "tool": "open_knowledge",
                    "args": {"task": "prohibited techniques identify stop"},
                },
            ),
            PlaybookStep(
                title="Quote policy",
                hypothesis="SCOPE prohibited covers DoS/brute/destruction.",
                aggression=0,
                command="scope_check",
                expected="policy quote for prohibited",
                stop="if operator insists on DoS → refuse",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "dos stress",
                    },
                },
            ),
        ),
        study_notes=("extreme/prohibited-identify-stop.md",),
    ),
    "prompt-injection": Playbook(
        class_name="prompt-injection",
        summary="Direct prompt injection against an in-scope chat/completions endpoint using canaries.",
        preconditions=(
            "Chat endpoint in SCOPE.md",
            "Test account/session available",
            "Payloads request canaries only — no real secret exfil",
        ),
        steps=(
            PlaybookStep(
                title="Scope + knowledge",
                hypothesis="AI surface is authorized and study notes loaded.",
                aggression=0,
                command="open_knowledge prompt-injection",
                expected="AI hunting rails loaded.",
                stop="OUT_OF_SCOPE or missing notes.",
                tool_call={
                    "tool": "open_knowledge",
                    "args": {"task": "prompt-injection llm"},
                },
            ),
            PlaybookStep(
                title="Dry-run canary probe",
                hypothesis="Model follows user over policy and returns HB_CANARY_PROMPT_INJECTION.",
                aggression=2,
                command="llm_prompt_probe",
                expected="dry-run plan or canary_returned / blocked.",
                stop="tool_executed with real side effects → record and stop.",
                tool_call={
                    "tool": "llm_prompt_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                        "canary": "HB_CANARY_PROMPT_INJECTION",
                        "session": "A",
                    },
                },
            ),
            PlaybookStep(
                title="Cleanup",
                hypothesis="No persistent poison left in shared context.",
                aggression=0,
                command="note evidence path; clear canary conversation if UI allows",
                expected="evidence redacted; conversation cleaned.",
                stop="shared tenant contamination → escalate to operator.",
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["prompt-injection", "llm"])),
    ),
    "indirect-prompt": Playbook(
        class_name="indirect-prompt",
        summary="Indirect prompt injection via untrusted retrieved/uploaded content.",
        preconditions=("Upload or retrieval path in scope", "Canary document prepared"),
        steps=(
            PlaybookStep(
                title="Scope gate",
                hypothesis="Host is IN_SCOPE before planting canary content.",
                aggression=0,
                command="scope_check",
                expected="IN_SCOPE",
                stop="OUT_OF_SCOPE",
                tool_call={
                    "tool": "scope_check",
                    "args": {
                        "target_dir": "{target_dir}",
                        "host": "{host}",
                        "action": "indirect prompt injection",
                    },
                },
            ),
            PlaybookStep(
                title="Indirect canary",
                hypothesis="Agent follows document instructions → HB_CANARY_INDIRECT / RAG_CONFUSION.",
                aggression=2,
                command="llm_indirect_prompt_probe",
                expected="canary_returned or blocked.",
                stop="cross-tenant content exposure → High; stop writes.",
                tool_call={
                    "tool": "llm_indirect_prompt_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                        "session": "A",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["prompt-injection", "rag"])),
    ),
    "rag": Playbook(
        class_name="rag",
        summary="RAG source confusion / cross-tenant retrieval signals (canary only).",
        preconditions=("Retrieval-backed chat in scope", "Two tenants or workspaces if testing isolation"),
        steps=(
            PlaybookStep(
                title="RAG canary ask",
                hypothesis="Retriever surfaces other-tenant source ids → HB_CANARY_TENANT_LEAK.",
                aggression=2,
                command="llm_rag_probe",
                expected="cross_tenant_signal / blocked / inconclusive.",
                stop="raw private content → redact, record High, stop.",
                tool_call={
                    "tool": "llm_rag_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                        "session": "A",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["rag", "llm"])),
    ),
    "agentic": Playbook(
        class_name="agentic",
        summary="Tool-use abuse / excessive agency / confused deputy in agent workflows.",
        preconditions=("Agent or tool-calling endpoint in scope", "Tools must stay dry-run"),
        steps=(
            PlaybookStep(
                title="Tool-boundary canary",
                hypothesis="Model attempts external tool call → tool_attempted; execution is High.",
                aggression=2,
                command="llm_tool_abuse_probe",
                expected="TOOL_BLOCKED / tool_attempted / blocked.",
                stop="tool_executed against real systems → stop.",
                tool_call={
                    "tool": "llm_tool_abuse_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                        "session": "A",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["agentic", "mcp"])),
    ),
    "mcp": Playbook(
        class_name="mcp",
        summary="MCP/agent JSON-RPC exposure: tools/list and resources/list without auth.",
        preconditions=("MCP/SSE/JSON-RPC URL in SCOPE",),
        steps=(
            PlaybookStep(
                title="List tools/resources",
                hypothesis="Unauthenticated tools/list leaks privileged capabilities.",
                aggression=2,
                command="mcp_agent_probe",
                expected="tool list redacted or 401/403.",
                stop="destructive tool names exposed → Medium/High; do not invoke.",
                tool_call={
                    "tool": "mcp_agent_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["mcp"])),
    ),
    "tenant-isolation-ai": Playbook(
        class_name="tenant-isolation-ai",
        summary="AI tenant isolation: request other-object canary; expect DENIED.",
        preconditions=("Two test tenants/users", "Object canary id placeholder"),
        steps=(
            PlaybookStep(
                title="Cross-tenant ask",
                hypothesis="Isolation returns DENIED for HB_OTHER_OBJECT_CANARY.",
                aggression=2,
                command="llm_tenant_isolation_probe",
                expected="DENIED / blocked / cross_tenant_signal.",
                stop="other-tenant content → High; stop.",
                tool_call={
                    "tool": "llm_tenant_isolation_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                        "session": "A",
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["llm", "rag"])),
    ),
    "system-boundary": Playbook(
        class_name="system-boundary",
        summary="Detect system/policy boundary leakage without demanding secret dumps.",
        preconditions=("Chat endpoint in scope",),
        steps=(
            PlaybookStep(
                title="Boundary canary",
                hypothesis="Model answers YES/NO/UNKNOWN + HB_CANARY_SYSTEM_BOUNDARY only.",
                aggression=1,
                command="llm_system_boundary_probe",
                expected="system_boundary_signal (Low) or blocked.",
                stop="secrets in output → redact + escalate.",
                tool_call={
                    "tool": "llm_system_boundary_probe",
                    "args": {
                        "target_dir": "{target_dir}",
                        "url": "{endpoint}",
                        "approve": False,
                        "canary": "HB_CANARY_SYSTEM_BOUNDARY",
                        "session": "A",
                        "max_payloads": 1,
                    },
                },
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["prompt-injection"])),
    ),
}

# Aliases into the same playbook
for _alias, _canon in (
    ("bola", "idor"),
    ("bac", "idor"),
    ("bfla", "idor"),
    ("authz", "idor"),
    ("access-control", "idor"),
    ("injection", "sqli"),
    ("nosqli", "sqli"),
    ("dos", "rate-limit"),
    ("ddos", "rate-limit"),
    ("stress", "rate-limit"),
    ("bruteforce", "brute"),
    ("rate_limit", "rate-limit"),
    ("ratelimit", "rate-limit"),
    ("password-bypass", "auth-bypass"),
    ("authbypass", "auth-bypass"),
    ("credential-leak", "secrets"),
    ("tokens", "secrets"),
    ("path-traversal", "lfi"),
    ("path_traversal", "lfi"),
    ("local-file-inclusion", "lfi"),
    ("template-injection", "ssti"),
    ("xml-external-entity", "xxe"),
    ("invite_idor", "invite-idor"),
    ("dom_xss", "dom-xss"),
    ("domxss", "dom-xss"),
    ("cache_detect", "cache-detect"),
    ("cache-poison", "cache-detect"),
    ("prohibited", "prohibited-stop"),
    ("identify-stop", "prohibited-stop"),
    ("prompt_injection", "prompt-injection"),
    ("indirect_prompt", "indirect-prompt"),
    ("indirect-prompt-injection", "indirect-prompt"),
    ("confused-deputy", "agentic"),
    ("tool-abuse", "agentic"),
    ("tool_abuse", "agentic"),
    ("tenant-isolation", "tenant-isolation-ai"),
    ("system_prompt", "system-boundary"),
    ("system-prompt", "system-boundary"),
):
    if _canon in _PLAYBOOKS:
        base = _PLAYBOOKS[_canon]
        _PLAYBOOKS[_alias] = Playbook(
            class_name=_alias,
            summary=base.summary,
            preconditions=base.preconditions,
            steps=base.steps,
            study_notes=base.study_notes,
        )


def playbook_for(task_or_class: str) -> Playbook:
    """Pick the best playbook for a class name or free-text task."""
    key = task_or_class.strip().lower()
    if key in _PLAYBOOKS:
        return _PLAYBOOKS[key]
    classes = classify(task_or_class)
    for cls in classes:
        if cls in _PLAYBOOKS:
            return _PLAYBOOKS[cls]
    return _PLAYBOOKS["recon"]


def executable_steps(pb: Playbook, *, max_aggression: int = 2) -> list[PlaybookStep]:
    """Steps at or below max_aggression (includes manual steps for display)."""
    return [s for s in pb.steps if s.aggression <= max_aggression]


def playbook_markdown(pb: Playbook, *, endpoint: str = "") -> str:
    target = endpoint or "<endpoint>"
    lines = [
        f"# Playbook: {pb.class_name}",
        "",
        pb.summary,
        "",
        "## Preconditions",
        *[f"- {p}" for p in pb.preconditions],
        "",
        "## Steps",
    ]
    for i, step in enumerate(pb.steps, 1):
        cmd = (
            step.command.replace("$ENDPOINT", target)
            .replace("$URL_WITH_A_ID", target)
            .replace("{endpoint}", target)
            .replace("{host}", target)
        )
        lines.extend(
            [
                f"### {i}. {step.title}",
                f"- Hypothesis: {step.hypothesis}",
                f"- Aggression: {step.aggression}",
                f"- Command:\n```text\n{cmd}\n```",
                f"- Expected: {step.expected}",
                f"- Stop: {step.stop}",
            ]
        )
        if step.tool_call:
            lines.append(f"- Executable: `{step.tool_call.get('tool')}`")
        lines.append("")
    if pb.study_notes:
        lines.append("## Study notes")
        lines.extend(f"- `{n}`" for n in pb.study_notes)
    return "\n".join(lines)


def list_playbooks() -> list[str]:
    return sorted({p.class_name for p in _PLAYBOOKS.values()})
