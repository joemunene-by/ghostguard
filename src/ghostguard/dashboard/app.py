"""FastAPI sub-application for the GhostGuard dashboard.

Serves a single-page HTML dashboard with REST API and WebSocket
endpoints for real-time audit event monitoring.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from ghostguard.audit.store import AuditStore
from ghostguard.dashboard.api import router as api_router
from ghostguard.dashboard.websocket import broadcaster, websocket_events

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def create_dashboard_app(audit_store: AuditStore) -> FastAPI:
    """Build the dashboard FastAPI sub-application.

    Parameters
    ----------
    audit_store:
        The shared audit store instance for querying events.

    Returns
    -------
    FastAPI
        A mountable sub-application.
    """
    dashboard = FastAPI(
        title="GhostGuard Dashboard",
        docs_url=None,
        redoc_url=None,
    )

    # Store reference for API endpoints
    dashboard.state.audit_store = audit_store
    dashboard.state.broadcaster = broadcaster

    # REST API routes
    dashboard.include_router(api_router)

    # WebSocket endpoint
    dashboard.add_api_websocket_route("/ws/events", websocket_events)

    # Serve the single-page dashboard
    @dashboard.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        template_path = _TEMPLATE_DIR / "index.html"
        if template_path.exists():
            html = template_path.read_text(encoding="utf-8")
        else:
            html = _FALLBACK_HTML
        return HTMLResponse(html)

    return dashboard


_FALLBACK_HTML = """\
<!DOCTYPE html>
<html>
<head><title>GhostGuard Dashboard</title></head>
<body style="background:#0a0a14;color:#eee;font-family:sans-serif;padding:2rem;">
  <h1>GhostGuard Dashboard</h1>
  <p>Template file not found. Place index.html in src/ghostguard/dashboard/templates/</p>
</body>
</html>
"""
