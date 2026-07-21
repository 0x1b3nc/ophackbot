"""Produce falsifiable hunting steps bound to scope and aggression level."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .knowledge import classify, notes_for_classes
from .policy_guard import ScopePolicy, host_from_target, policy_quote_for


@dataclass(frozen=True)
class HuntStep:
    hypothesis: str
    target: str
    preconditions: list[str]
    aggression: int
    policy_quote: str
    command: str
    expected_evidence: str
    stop_criteria: str
    cleanup: str
    study_notes: list[str]
    in_scope: bool
    notes: str = ""

    def to_markdown(self) -> str:
        notes = "\n".join(f"- {n}" for n in self.study_notes) or "- (none matched)"
        pre = "\n".join(f"- {p}" for p in self.preconditions)
        return f"""# Hunt Step

## Hypothesis
{self.hypothesis}

## Target / endpoint
`{self.target}`

## Preconditions
{pre}

## Aggression level
{self.aggression}

## Policy authorization
> {self.policy_quote}

## Concrete command / script
```text
{self.command}
```

## Expected evidence
{self.expected_evidence}

## Stop criteria
{self.stop_criteria}

## Cleanup
{self.cleanup}

## Study notes opened
{notes}

## Scope status
in_scope={self.in_scope}
{self.notes}
"""


def plan_step(
    target_dir: Path,
    *,
    hypothesis: str,
    target: str,
    action: str,
    command: str,
    expected_evidence: str = "Differential response or confirmed impact with negative control.",
    stop_criteria: str = "Hypothesis falsified, impact proved, or policy limit hit.",
    cleanup: str = "Stop traffic; redact evidence; restore any test state you created.",
    preconditions: list[str] | None = None,
) -> HuntStep:
    policy = ScopePolicy.load(target_dir)
    host = host_from_target(target)
    in_scope = policy.contains_host(host) if host else False
    aggression = policy.classify_aggression(action)
    quote = policy_quote_for(policy, aggression)
    classes = classify(f"{hypothesis} {action}")
    notes = [str(p) for p in notes_for_classes(classes)]

    warnings: list[str] = []
    if not in_scope:
        warnings.append(
            "NOT_CONFIRMED in SCOPE.md. Do not send active traffic. "
            "This is inference until the host appears in scope text."
        )
    if aggression >= 2 and not policy.mentions_active_testing():
        warnings.append(
            "Level >=2 requested but SCOPE.md does not clearly authorize active testing."
        )
    if aggression >= 3 and not policy.allows_level3():
        warnings.append(
            "Level 3 requested but policy does not explicitly allow brute/DoS/stress."
        )

    return HuntStep(
        hypothesis=hypothesis,
        target=target,
        preconditions=preconditions
        or [
            "SCOPE.md present and reviewed",
            "Host confirmed in-scope",
            f"Aggression {aggression} authorized by policy quote",
        ],
        aggression=aggression,
        policy_quote=quote,
        command=command,
        expected_evidence=expected_evidence,
        stop_criteria=stop_criteria,
        cleanup=cleanup,
        study_notes=notes,
        in_scope=in_scope,
        notes="\n".join(warnings),
    )


def step_as_dict(step: HuntStep) -> dict:
    return asdict(step)
