from dataclasses import dataclass


@dataclass(frozen=True)
class RuleResult:
    """A rule's graded output: a 0-100 score, not just a pass/fail flag."""

    rule: str
    score: float
    triggered: bool
    detail: str = ""
