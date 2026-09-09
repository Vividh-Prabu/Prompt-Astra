from typing import List, Optional
from pydantic import BaseModel, Field

try:
    from config import MAX_PROMPT_LENGTH
except ImportError:
    try:
        from .config import MAX_PROMPT_LENGTH
    except ImportError:
        MAX_PROMPT_LENGTH = 4096


class RiskBreakdown(BaseModel):
    ml_confidence_score: float = 0.0
    instruction_override_risk: float = 0.0
    system_leak_risk: float = 0.0
    privilege_escalation_risk: float = 0.0
    obfuscation_risk: float = 0.0
    entropy_score: float = 0.0


# Alias for backward compatibility
BreakdownScores = RiskBreakdown


class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., max_length=MAX_PROMPT_LENGTH)
    sanitize: bool = True
    store_event: bool = False  # Only persist to database when True


class AnalyzeResponse(BaseModel):
    label: str
    decision: str
    risk_score: int
    confidence: float = 95.0
    latency_ms: float = 0.0
    explanation: str
    suspicious_matches: List[str] = Field(default_factory=list)
    breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)
    sanitized_prompt: Optional[str] = None


class BatchAnalyzeRequest(BaseModel):
    prompts: List[str] = Field(..., min_items=1)


class BatchAnalyzeResponse(BaseModel):
    total_processed: int
    threats_blocked: int
    results: List[AnalyzeResponse]


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    version: str = "2.0.0"