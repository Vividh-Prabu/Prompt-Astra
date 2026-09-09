from fastapi import APIRouter, HTTPException, Query, status

from app.database import ServiceClientConfigurationError, get_service_supabase


router = APIRouter()


@router.get("/logs")
async def get_logs(limit: int = Query(default=50, ge=1, le=100)):
    """Return the newest security events first."""
    try:
        service_supabase = get_service_supabase()
        result = (
            service_supabase.table("security_events")
            .select(
                "id,prompt,decision,risk_score,threat_category,reason,"
                "rule_score,ml_score,created_at"
            )
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
    except ServiceClientConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve security event logs.",
        ) from exc

    return {"events": result.data}
