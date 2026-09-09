from supabase import create_client, Client
from app.config import SUPABASE_KEY, SUPABASE_SERVICE_KEY, SUPABASE_URL

# Single reusable Supabase client instance
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

_service_supabase: Client | None = None


class ServiceClientConfigurationError(RuntimeError):
    """Raised when the backend read client has not been configured."""


def get_service_supabase() -> Client:
    """Return the server-only Supabase client used for privileged reads."""
    global _service_supabase

    if not SUPABASE_SERVICE_KEY:
        raise ServiceClientConfigurationError(
            "Backend configuration error: SUPABASE_SERVICE_KEY is not configured."
        )

    if _service_supabase is None:
        _service_supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

    return _service_supabase
