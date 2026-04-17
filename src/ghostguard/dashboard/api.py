"""Dashboard REST API endpoints.

Serves paginated audit events and aggregated statistics for the
GhostGuard web dashboard.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Query, Request

from ghostguard.audit.store import AuditStore

router = APIRouter(prefix="/api", tags=["dashboard"])


def _get_store(request: Request) -> AuditStore:
    """Retrieve the AuditStore from the app state."""
    return request.app.state.audit_store


@router.get("/events")
async def list_events(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = Query(None),
    tool: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
) -> dict[str, Any]:
    """Return paginated audit events with optional filters.

    Query parameters:
    - ``limit``: max events to return (default 50, max 500)
    - ``offset``: skip this many events
    - ``verdict``: filter by verdict (allow/deny/sandbox)
    - ``tool``: filter by tool name
    - ``session_id``: filter by session
    """
    store = _get_store(request)
    events = await store.query(
        limit=limit,
        offset=offset,
        tool_name=tool,
        verdict=verdict,
        session_id=session_id,
    )
    total = await store.count()

    return {
        "events": [e.to_dict() for e in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/stats")
async def get_stats(request: Request) -> dict[str, Any]:
    """Return aggregated audit statistics.

    Response includes:
    - ``total``: total event count
    - ``by_verdict``: counts keyed by verdict
    - ``top_blocked_tools``: top 10 denied tools
    - ``events_per_hour``: hourly event counts for the last 24h
    """
    store = _get_store(request)
    return await store.stats()
