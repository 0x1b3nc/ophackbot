"""Class playbooks: knowledge routed into falsifiable next steps."""

from __future__ import annotations

from dataclasses import dataclass

from .knowledge import classify, notes_for_classes


@dataclass(frozen=True)
class PlaybookStep:
    title: str
    hypothesis: str
    aggression: int
    command: str
    expected: str
    stop: str


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
                title="Baseline as owner",
                hypothesis="Owner A can read their own object at the candidate endpoint.",
                aggression=1,
                command='curl -i "$URL_WITH_A_ID" -H "Cookie: SESSION=A"  # expect 200 + A data',
                expected="200 with A-owned fields.",
                stop="Auth fails, 404 for owner, or endpoint not confirmed.",
            ),
            PlaybookStep(
                title="Cross-account swap",
                hypothesis="User B can read A's object by swapping only the object ID.",
                aggression=2,
                command='curl -i "$URL_WITH_A_ID" -H "Cookie: SESSION=B"  # secure: 403/404; vuln: 200 + A data',
                expected="Secure: 403/404. Vulnerable: 200 with A's private data.",
                stop="Any unexpected write, rate-limit, or out-of-scope host.",
            ),
            PlaybookStep(
                title="Negative control",
                hypothesis="Random/nonexistent IDs do not leak other tenants.",
                aggression=1,
                command='curl -i "$URL_WITH_RANDOM_ID" -H "Cookie: SESSION=B"',
                expected="404/403, not another user's data.",
                stop="Stop after one clean A/B pair + negative control.",
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
                title="Benign fetch",
                hypothesis="The app fetches the URL I supply and returns or logs the response.",
                aggression=1,
                command='curl -i "$ENDPOINT" -d "url=https://example.com/"',
                expected="Response/log shows fetched content or error from remote.",
                stop="No fetch behavior; parameter ignored.",
            ),
            PlaybookStep(
                title="Internal probe (policy permitting)",
                hypothesis="The server can reach link-local/metadata or internal hosts.",
                aggression=2,
                command='curl -i "$ENDPOINT" -d "url=http://127.0.0.1/"  # or metadata IP if SCOPE allows',
                expected="Internal banner/body vs external control proves SSRF.",
                stop="Level-3 / cloud metadata prohibited by SCOPE; stop immediately.",
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
                title="Canary reflect",
                hypothesis="My marker string is reflected into the response body unencoded.",
                aggression=1,
                command='curl -i "$ENDPOINT?q=hackbotXSS1337"',
                expected="Marker appears in HTML/JS context.",
                stop="No reflection.",
            ),
            PlaybookStep(
                title="Minimal probe",
                hypothesis="A minimal HTML/JS breakout executes in the reflected context.",
                aggression=2,
                command='curl -i "$ENDPOINT?q=<svg/onload=alert(1)>"  # ACTIVE only if SCOPE allows',
                expected="Sink executes or CSP blocks with evidence of injection point.",
                stop="CSP hard-block with no bypass angle; do not spray payloads.",
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
                title="Baseline",
                hypothesis="Normal value returns a stable response shape.",
                aggression=1,
                command='curl -i "$ENDPOINT?id=1"',
                expected="Stable 200 body length/status.",
                stop="Unstable endpoint; fix baseline first.",
            ),
            PlaybookStep(
                title="Boolean differential",
                hypothesis="True/false probes change status or body in a query-dependent way.",
                aggression=2,
                command='curl -i "$ENDPOINT?id=1 AND 1=1" ; curl -i "$ENDPOINT?id=1 AND 1=2"',
                expected="Clear differential between true/false; not just WAF noise.",
                stop="WAF 403 loop, errors without differential, or SCOPE forbids injection tests.",
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
                title="Single-thread limit",
                hypothesis="The limit/coupon/balance enforces correctly for one request at a time.",
                aggression=1,
                command='curl -i -X POST "$ENDPOINT" -H "Cookie: SESSION=A" -d "..."',
                expected="Limit holds for sequential calls.",
                stop="Action not reversible; abort.",
            ),
            PlaybookStep(
                title="Parallel burst",
                hypothesis="N concurrent requests bypass the limit once.",
                aggression=2,
                command="seq 1 5 | xargs -P5 -I{} curl -s -o /dev/null -w '%{http_code}\\n' -X POST \"$ENDPOINT\" ...",
                expected="More successes than the limit allows.",
                stop="One burst only; clean up created objects; no DoS flooding.",
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
                command="hackbot: scope_check on targets/<program> --host <host>",
                expected="IN_SCOPE status.",
                stop="NOT_CONFIRMED or OUT_OF_SCOPE.",
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
            ),
        ),
        study_notes=tuple(str(p) for p in notes_for_classes(["recon"])),
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
        cmd = step.command.replace("$ENDPOINT", target).replace("$URL_WITH_A_ID", target)
        lines.extend(
            [
                f"### {i}. {step.title}",
                f"- Hypothesis: {step.hypothesis}",
                f"- Aggression: {step.aggression}",
                f"- Command:\n```text\n{cmd}\n```",
                f"- Expected: {step.expected}",
                f"- Stop: {step.stop}",
                "",
            ]
        )
    if pb.study_notes:
        lines.append("## Study notes")
        lines.extend(f"- `{n}`" for n in pb.study_notes)
    return "\n".join(lines)


def list_playbooks() -> list[str]:
    return sorted({p.class_name for p in _PLAYBOOKS.values()})
