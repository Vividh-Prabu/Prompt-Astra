from fastapi import APIRouter, HTTPException, status

from app.models.request_models import AnalyzeRequest
from app.models.response_models import AnalyzeResponse
from app.database import supabase
from app.services.ml_detector import ModelUnavailableError, analyze_with_model
from app.services.policy_engine import determine_decision
from app.services.risk_scorer import calculate_risk_score
from app.services.rule_engine import analyze_rules

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(request: AnalyzeRequest):
    print("🔥 UPDATED ANALYZE ENDPOINT CALLED")
    print("📝 Received prompt:", request.prompt)

    # 1. Analyze prompt using rules
    rule_analysis = analyze_rules(request.prompt)

    # 2. Analyze prompt using ML model
    try:
        ml_analysis = analyze_with_model(request.prompt)
    except ModelUnavailableError as exc:
        print("❌ ML model unavailable:", repr(exc))

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Security model is unavailable: {exc}",
        ) from exc

    # 3. Calculate combined risk score
    risk_score = calculate_risk_score(
        rule_analysis.rule_score,
        ml_analysis.ml_score,
    )

    # 4. Determine final decision
    decision = determine_decision(risk_score)

    # 5. Determine threat category and reason
    if rule_analysis.rule_score > 0:
        threat_category = rule_analysis.threat_category
        reason = rule_analysis.reason
    else:
        threat_category = ml_analysis.predicted_category
        reason = (
            f"ML model predicted category: "
            f"{ml_analysis.predicted_category}."
        )

    # 6. Create API response
    response = AnalyzeResponse(
        decision=decision,
        risk_score=risk_score,
        threat_category=threat_category,
        reason=reason,
    )

    print("📊 Analysis result:", response)

    # 7. Save event to Supabase
    print("🟡 ABOUT TO INSERT INTO SUPABASE")

    try:
        db_response = (
            supabase
            .table("security_events")
            .insert({
                "prompt": request.prompt,
                "decision": response.decision,
                "risk_score": response.risk_score,
                "threat_category": response.threat_category,
            })
            .execute()
        )

        print("🟢 SUPABASE INSERT RESPONSE:", db_response.data)

    except Exception as exc:
        print("🔴 SUPABASE INSERT FAILED:", repr(exc))

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to persist security event: {exc}",
        ) from exc

    # 8. Return response to frontend
    print("✅ Returning response to frontend")

    return response