from app.utils.constants import ALLOW, BLOCK, REVIEW


def determine_decision(risk_score: float) -> str:
    """Apply the Stage 2 policy thresholds to a normalized risk score."""
    if risk_score >= 0.70:
        return BLOCK
    if risk_score >= 0.40:
        return REVIEW
    return ALLOW
