from collections import Counter

from fastapi import APIRouter, HTTPException, status

from app.database import ServiceClientConfigurationError, get_service_supabase
from app.utils.constants import ALLOW, BLOCK, REVIEW


router = APIRouter()


@router.get("/stats")
async def get_stats():
    """Return aggregate counts derived from the security event log."""
    try:
        service_supabase = get_service_supabase()
        result = service_supabase.table("security_events").select(
            "decision,threat_category"
        ).execute()
    except ServiceClientConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to retrieve security event statistics.",
        ) from exc

    events = result.data or []
    decisions = Counter(event.get("decision") for event in events)
    categories = Counter(
        event.get("threat_category") or "None" for event in events
    )

    return {
        "total_requests": len(events),
        "allowed": decisions[ALLOW],
        "review": decisions[REVIEW],
        "blocked": decisions[BLOCK],
        "threat_category_counts": dict(categories),
    }
