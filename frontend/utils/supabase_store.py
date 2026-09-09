"""
Supabase integration for the PromptAstra / PromptGuard frontend.

WHY THIS EXISTS
    The FastAPI backend records every analysed prompt into a Supabase table
    called `security_events`. Previously the Flask UI only read static demo
    JSON, so it never showed those real events. This module connects the UI to
    Supabase so the dashboard, monitor, and review queue reflect live data.

DESIGN PRINCIPLES
    * Fail-safe: if Supabase is not configured or is unreachable, every method
      returns `None`/`False` and the caller falls back to the demo JSON. The UI
      must never crash just because the database is down.
    * Single source of truth for the table SCHEMA, matched to what the backend
      writes/reads:
          id, prompt, decision, risk_score, threat_category,
          reason, rule_score, ml_score, created_at
    * Pure mapping helpers (module-level functions) are easy to unit-test.

CONFIGURATION (frontend/.env)
    SUPABASE_URL=...           # your project URL
    SUPABASE_KEY=...           # a Supabase API key (see .env.example)
    # Optional, takes priority if set:
    SUPABASE_SERVICE_KEY=...   # service-role key for server-side reads/writes
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load frontend/.env once, at import time. `override=False` means real
# environment variables (e.g. set in production) win over the file.
_FRONTEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=_FRONTEND_DIR / ".env", override=False)

TABLE_NAME = "security_events"


# --------------------------------------------------------------------------- #
# Pure mapping helpers (no I/O — trivially unit-testable)
# --------------------------------------------------------------------------- #
def severity_from_score(score: Any) -> str:
    """Map a 0-100 risk score to a severity band the templates understand."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "LOW"
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def prettify_category(category: Optional[str]) -> str:
    """Turn 'PROMPT_INJECTION' into 'Prompt Injection'; handle empties."""
    if not category or str(category).upper() in {"NONE", "SAFE", "BENIGN", ""}:
        return "Benign Request"
    return str(category).replace("_", " ").title()


def status_from_decision(decision: Optional[str]) -> str:
    """Human-readable gateway status derived from the decision."""
    decision = (decision or "").upper()
    if decision == "BLOCK":
        return "Blocked at Gateway"
    if decision == "REVIEW":
        return "Awaiting Human Review"
    return "Forwarded to ARGUS"


def _confidence_from(ml_score: Any, fallback: int = 90) -> int:
    """Derive a display confidence (1-99) from the model score if present."""
    try:
        if ml_score is None:
            return fallback
        pct = round(float(ml_score) * 100)
        return max(1, min(99, pct))
    except (TypeError, ValueError):
        return fallback


def _format_timestamp(created_at: Optional[str]) -> str:
    """Format an ISO timestamp from Supabase as 'YYYY-MM-DD HH:MM:SS'."""
    if not created_at:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw = str(created_at).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        # Fall back to a trimmed version of whatever we were given.
        return str(created_at)[:19].replace("T", " ")


def map_row_to_event(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert one `security_events` row into the event dict the UI templates
    expect (same shape as the demo threat_history entries).
    """
    prompt = row.get("prompt") or ""
    risk_score = row.get("risk_score") or 0
    decision = (row.get("decision") or "ALLOW").upper()
    reason = row.get("reason") or ""
    snippet = prompt.strip()[:90] + ("..." if len(prompt.strip()) > 90 else "")

    return {
        "id": str(row.get("id", "")),
        "timestamp": _format_timestamp(row.get("created_at")),
        "prompt_snippet": snippet,
        "full_prompt": prompt,
        "attack_type": prettify_category(row.get("threat_category")),
        "severity": severity_from_score(risk_score),
        "risk_score": risk_score,
        "confidence": _confidence_from(row.get("ml_score")),
        "decision": decision,
        "status": status_from_decision(decision),
        "argus_exposed": decision == "ALLOW",
        "signals": [reason] if reason else [],
        "explanation": reason,
    }


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #
class SupabaseStore:
    """Thin, fail-safe wrapper around the Supabase `security_events` table."""

    def __init__(self) -> None:
        self.url = os.environ.get("SUPABASE_URL", "").strip()
        # Prefer a service-role key for server-side use; fall back to any key.
        self.key = (
            os.environ.get("SUPABASE_SERVICE_KEY")
            or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_KEY")
            or os.environ.get("SUPABASE_ANON_KEY")
            or ""
        ).strip()
        # If the frontend is pointed at the FastAPI backend (which logs to
        # Supabase itself), set FRONTEND_WRITES_SUPABASE=0 to avoid double
        # writes. Defaults to enabled, so the standalone UI is self-sufficient.
        self.writes_enabled = os.environ.get(
            "FRONTEND_WRITES_SUPABASE", "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        self._client = None
        self._init_error: Optional[str] = None
        self._connect()

    def _connect(self) -> None:
        """Create the client once. Never raises — records the error instead."""
        if not self.url or not self.key:
            self._init_error = "SUPABASE_URL / SUPABASE_KEY not set"
            return
        try:
            from supabase import create_client  # imported lazily

            self._client = create_client(self.url, self.key)
        except Exception as exc:  # noqa: BLE001 - stay fail-safe
            self._init_error = f"{type(exc).__name__}: {exc}"
            self._client = None

    @property
    def is_configured(self) -> bool:
        """True only when a live client was created successfully."""
        return self._client is not None

    @property
    def status_message(self) -> str:
        """Short human-readable status, handy for a health endpoint."""
        if self.is_configured:
            return "connected"
        return f"disabled ({self._init_error})" if self._init_error else "disabled"

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def fetch_events(
        self,
        limit: int = 50,
        attack_type: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Return the newest events (mapped to the UI shape), or None on failure.

        Filtering by attack_type/decision is applied in Python after fetching,
        so it works even though categories are stored in UPPER_SNAKE form.
        """
        if not self.is_configured:
            return None
        try:
            # Fetch a little extra so post-filtering can still fill `limit`.
            query = (
                self._client.table(TABLE_NAME)
                .select("*")
                .order("created_at", desc=True)
                .limit(max(limit * 3, limit))
            )
            result = query.execute()
        except Exception:  # noqa: BLE001
            return None

        events = [map_row_to_event(r) for r in (result.data or [])]

        if attack_type and attack_type != "ALL":
            events = [
                e for e in events
                if e["attack_type"].lower() == attack_type.lower()
            ]
        if decision and decision != "ALL":
            events = [
                e for e in events if e["decision"] == decision.upper()
            ]
        return events[:limit]

    def get_live_stats(self) -> Optional[Dict[str, Any]]:
        """
        Aggregate live KPI counts and a threat distribution from Supabase.

        Returns a dict shaped to overlay onto system_stats.json:
            {"kpis": {...}, "threat_distribution": [...]}
        or None if Supabase is unavailable.
        """
        if not self.is_configured:
            return None
        try:
            result = (
                self._client.table(TABLE_NAME)
                .select("decision,risk_score,threat_category")
                .execute()
            )
        except Exception:  # noqa: BLE001
            return None

        rows = result.data or []
        total = len(rows)
        blocked = sum(1 for r in rows if (r.get("decision") or "").upper() == "BLOCK")
        reviewed = sum(1 for r in rows if (r.get("decision") or "").upper() == "REVIEW")
        allowed = sum(1 for r in rows if (r.get("decision") or "").upper() == "ALLOW")
        threats = blocked + reviewed

        scores = [float(r.get("risk_score") or 0) for r in rows]
        avg_risk = round(sum(scores) / total, 1) if total else 0.0

        def pct(part: int) -> float:
            return round((part / total) * 100, 1) if total else 0.0

        # Build a threat distribution grouped by prettified category.
        from collections import Counter

        cat_counts = Counter(
            prettify_category(r.get("threat_category")) for r in rows
        )
        distribution = [
            {
                "category": cat,
                "count": count,
                "percentage": pct(count),
                "severity": "CRITICAL" if "Injection" in cat or "Jailbreak" in cat
                else ("HIGH" if cat != "Benign Request" else "LOW"),
            }
            for cat, count in cat_counts.most_common()
        ]

        return {
            "kpis": {
                "total_requests": total,
                "threats_detected": threats,
                "requests_blocked": blocked,
                "requests_reviewed": reviewed,
                "requests_allowed": allowed,
                "block_rate": pct(blocked),
                "review_rate": pct(reviewed),
                "allow_rate": pct(allowed),
                "avg_risk_score": avg_risk,
                "review_queue_pending": reviewed,
            },
            "threat_distribution": distribution,
        }

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #
    def insert_event(
        self, prompt: str, analysis: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Persist an analysed prompt to Supabase and return the mapped event.

        Returns None on any failure so the caller falls back to local JSON.
        The inserted columns match the backend's `security_events` schema.
        """
        if not self.is_configured or not self.writes_enabled:
            return None

        category = (analysis.get("attack_type") or "None")
        record = {
            "prompt": (prompt or "").strip(),
            "decision": (analysis.get("decision") or "ALLOW").upper(),
            "risk_score": int(analysis.get("risk_score") or 0),
            "threat_category": category.upper().replace(" ", "_"),
            "reason": analysis.get("explanation") or "",
            # ml_score / rule_score are stored as 0-1 fractions like the backend.
            "ml_score": round(float(analysis.get("confidence") or 0) / 100.0, 4),
            "rule_score": round(float(analysis.get("risk_score") or 0) / 100.0, 4),
        }
        try:
            result = self._client.table(TABLE_NAME).insert(record).execute()
        except Exception:  # noqa: BLE001
            return None

        rows = result.data or []
        if not rows:
            return None
        return map_row_to_event(rows[0])

    def update_decision(self, event_id: str, decision: str) -> bool:
        """
        Update the decision for a live event (used by the review queue).

        Status/reviewer columns don't exist in the base schema, so we persist
        only the decision change. Returns True on success.

        The id is used as-is (a string): this works whether the table's primary
        key is a UUID (e.g. 'bbffe938-...') or a bigint. Coercing to int here
        was a bug that made every review action fail on UUID-keyed tables.
        """
        if not self.is_configured or not event_id:
            return False
        try:
            self._client.table(TABLE_NAME).update(
                {"decision": decision.upper()}
            ).eq("id", str(event_id)).execute()
            return True
        except Exception:  # noqa: BLE001
            return False


# Singleton used across the app.
supabase_store = SupabaseStore()