import sys
import time
from pathlib import Path

FASTAPI_DIR = Path(__file__).resolve().parent.parent
if str(FASTAPI_DIR) not in sys.path:
    sys.path.insert(0, str(FASTAPI_DIR))

try:
    from ml_service import ml_service
    from schemas import (
        AnalyzeRequest,
        AnalyzeResponse,
        BatchAnalyzeRequest,
        BatchAnalyzeResponse,
        RiskBreakdown,
    )
    from security_engine import (
        calculate_shannon_entropy,
        run_heuristic_scan,
        sanitize_prompt,
    )
except ImportError:
    from ..ml_service import ml_service
    from ..schemas import (
        AnalyzeRequest,
        AnalyzeResponse,
        BatchAnalyzeRequest,
        BatchAnalyzeResponse,
        RiskBreakdown,
    )
    from ..security_engine import (
        calculate_shannon_entropy,
        run_heuristic_scan,
        sanitize_prompt,
    )


def analyze_single_prompt(payload: AnalyzeRequest) -> AnalyzeResponse:
    start_time = time.perf_counter()
    prompt = payload.prompt or ""
    lower_p = prompt.lower()

    # 1. Multi-vector heuristic scan & entropy calculation
    heuristic_matches, category_scores = run_heuristic_scan(prompt)
    entropy = calculate_shannon_entropy(prompt)

    # 2. Key threat category scores
    override_score = category_scores.get("instruction_override", 0.0)
    leak_score = max(category_scores.get("system_leak", 0.0), category_scores.get("system_prompt_leak", 0.0), category_scores.get("data_exfiltration", 0.0))
    jailbreak_score = category_scores.get("jailbreak", 0.0)
    obfuscation_score = category_scores.get("obfuscation", 0.0)
    
    max_heuristic_risk = max(override_score, leak_score, jailbreak_score, obfuscation_score)

    # 3. Direct extraction & injection signature triggers
    has_system_leak_pattern = any(
        k in lower_p for k in [
            "hidden instructions", "system prompt", "internal instructions",
            "controlling your behavior", "reveal instructions", "dump prompt"
        ]
    )
    if has_system_leak_pattern:
        leak_score = max(leak_score, 0.92)
        heuristic_matches.append("System prompt extraction signature detected")

    # 4. ML Inference
    if hasattr(ml_service, "analyze_prompt_text"):
        result, confidence, base_risk, _, ml_matches = ml_service.analyze_prompt_text(prompt)
    else:
        result = "safe"
        confidence = 95.0
        base_risk = 5.0
        ml_matches = []

    all_matches = list(set(heuristic_matches + ml_matches))
    is_ml_threat = str(result).lower() not in ["safe", "benign", "normal"]

    # 5. Synchronized 3-Tier Policy Engine Mapping
    if leak_score >= 0.6 or override_score >= 0.6 or jailbreak_score >= 0.6 or (is_ml_threat and confidence >= 70.0):
        decision = "BLOCK"
        if leak_score >= 0.6:
            label = "SYSTEM_LEAK"
            risk_score = int(max(leak_score * 100, 88))
            explanation = "Direct system prompt or internal instruction extraction attempt detected."
        elif override_score >= 0.6:
            label = "INSTRUCTION_OVERRIDE"
            risk_score = int(max(override_score * 100, 85))
            explanation = "Direct instruction override or directive suppression attempt detected."
        else:
            label = "PROMPT_INJECTION"
            risk_score = int(max(confidence, 85))
            explanation = all_matches[0] if all_matches else "High-confidence prompt injection attack."

    elif (
        is_ml_threat
        or (35.0 <= confidence < 70.0)
        or (max_heuristic_risk >= 0.35)
        or (entropy > 4.5)
        or any(k in lower_p for k in ["hypothetically", "unrestricted", "urgent", "bypass", "audit", "override tone"])
    ):
        decision = "REVIEW"
        risk_score = int(min(max(confidence, max_heuristic_risk * 100, 52), 74))
        label = "POLICY_TENSION" if not is_ml_threat else str(result).upper().replace(" ", "_")
        explanation = "Borderline semantic policy ambiguity. Quarantined for human review."
        if not all_matches:
            all_matches.append("Borderline policy tension requiring oversight")

    else:
        decision = "ALLOW"
        risk_score = int(min(base_risk, 15))
        label = "SAFE"
        explanation = "No suspicious intent detected."

    sanitized = sanitize_prompt(prompt) if getattr(payload, "sanitize", True) else None
    latency = round((time.perf_counter() - start_time) * 1000, 2)

    breakdown = RiskBreakdown(
        ml_confidence_score=round(float(confidence), 2),
        instruction_override_risk=round(float(override_score), 2),
        system_leak_risk=round(float(leak_score), 2),
        privilege_escalation_risk=round(float(category_scores.get("privilege_escalation", 0.0)), 2),
        obfuscation_risk=round(float(obfuscation_score), 2),
        entropy_score=round(float(entropy), 2),
    )

    return AnalyzeResponse(
        label=label,
        decision=decision,
        risk_score=risk_score,
        confidence=confidence,
        latency_ms=latency,
        explanation=explanation,
        suspicious_matches=all_matches,
        breakdown=breakdown,
        sanitized_prompt=sanitized,
    )


def analyze_batch_prompts(batch: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    results = [analyze_single_prompt(AnalyzeRequest(prompt=p)) for p in batch.prompts]
    blocked_count = sum(1 for r in results if r.decision in ["BLOCK", "REVIEW"])
    return BatchAnalyzeResponse(
        total_processed=len(results),
        threats_blocked=blocked_count,
        results=results,
    )