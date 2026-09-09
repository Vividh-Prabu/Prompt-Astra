from pydantic import BaseModel

class AnalyzeResponse(BaseModel):
    decision: str
    risk_score: float
    threat_category: str
    reason: str
