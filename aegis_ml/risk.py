DEFAULT_RULE_WEIGHT = 0.5


def combined_risk_score(rule_score: float, model_score: float, *, rule_weight: float = DEFAULT_RULE_WEIGHT) -> float:
    """Blend the rule engine's score with the anomaly model's score.

    ``rule_weight`` (0-1) is how much the rule-based score counts for;
    the model score gets the remainder. Exact weighting is tuned during
    threshold calibration -- this just needs to combine two 0-100 scores
    into one, staying in range.
    """
    rule_weight = max(0.0, min(1.0, rule_weight))
    blended = rule_score * rule_weight + model_score * (1.0 - rule_weight)
    return max(0.0, min(100.0, blended))
