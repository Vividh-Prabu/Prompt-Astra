def calculate_risk_score(rule_score: float, ml_score: float) -> float:
    """Combine detector scores using the Stage 2 equal-weight formula."""
    score = (0.5 * rule_score) + (0.5 * ml_score)
    return max(0.0, min(1.0, score))
