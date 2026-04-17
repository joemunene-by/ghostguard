"""FastAPI application factory for GhostGuard proxy.

Wires together the upstream client, policy engine, interceptor,
audit store, middleware, and optionally the dashboard sub-app.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from ghostguard.audit.store import AuditStore
from ghostguard.proxy.interceptor import ToolCallInterceptor
from ghostguard.proxy.middleware import RequestIdMiddleware, TimingMiddleware, setup_cors
from ghostguard.proxy.routes import router, set_dependencies
from ghostguard.proxy.upstream import UpstreamClient

logger = logging.getLogger(__name__)


def _load_policy_engine(policy_path: str) -> Any:
    """Load the policy engine from a YAML file.

    Tries to import the PolicyEngine from the policy module built by the
    other agent.  Falls back to a permissive stub so the proxy can start
    even before the policy engine is ready.
    """
    try:
        from ghostguard.policy.engine import PolicyEngine

        engine = PolicyEngine.from_yaml(policy_path)
        logger.info("Loaded policy engine from %s", policy_path)
        return engine
    except (ImportError, FileNotFoundError, Exception) as exc:
        logger.warning("Could not load PolicyEngine (%s); using permissive stub", exc)
        return _StubPolicyEngine(policy_path)


class _StubPolicyEngine:
    """Permissive stub used when the real PolicyEngine is not available."""

    version = "stub-1.0"

    def __init__(self, policy_path: str) -> None:
        self.policy_path = policy_path
        self.name = "stub-allow-all"

    async def evaluate(self, tool_call: Any) -> Any:
        from ghostguard._types import Decision, Verdict

        return Decision(
            verdict=Verdict.ALLOW,
            reason="Stub policy — allow all (policy engine not loaded)",
            tier="stub",
        )


def create_app(
    policy_path: str = "policy.yaml",
    upstream_url: str = "https://api.openai.com",
    db_path: str = "ghostguard.db",
    dashboard_enabled: bool = True,
) -> FastAPI:
    """Build and return the configured FastAPI application.

    Parameters
    ----------
    policy_path:
        Path to the YAML policy file.
    upstream_url:
        Base URL of the upstream LLM API.
    db_path:
        Path to the SQLite audit database.
    dashboard_enabled:
        Mount the web dashboard at ``/dashboard``.
    """
    # State shared via closure and lifespan
    state: dict[str, Any] = {
        "policy_path": policy_path,
        "upstream_url": upstream_url,
        "db_path": db_path,
        "dashboard_enabled": dashboard_enabled,
    }

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # --- Startup ---
        start_time = time.time()

        # Audit store
        audit_store = AuditStore(state["db_path"])
        await audit_store.initialize()
        app.state.audit_store = audit_store

        # Policy engine
        engine = _load_policy_engine(state["policy_path"])
        app.state.policy_engine = engine
        # Extract policy name from engine
        try:
            policy_name = engine._current_policy.metadata.name
        except Exception:
            policy_name = getattr(engine, "name", "unknown")

        # Upstream client
        upstream = UpstreamClient(state["upstream_url"])
        app.state.upstream = upstream

        # Interceptor
        interceptor = ToolCallInterceptor(engine, audit_store)
        app.state.interceptor = interceptor

        # Wire routes
        set_dependencies(upstream, interceptor, start_time, policy_name)

        # Dashboard
        if state["dashboard_enabled"]:
            try:
                from ghostguard.dashboard.app import create_dashboard_app
                from ghostguard.dashboard.websocket import broadcaster

                dashboard_app = create_dashboard_app(audit_store)
                app.mount("/dashboard", dashboard_app, name="dashboard")

                # Patch the audit store to broadcast events via WebSocket
                _original_log = audit_store.log

                async def _log_and_broadcast(event: Any) -> None:
                    await _original_log(event)
                    await broadcaster.broadcast(event.to_dict())

                audit_store.log = _log_and_broadcast  # type: ignore[assignment]
                logger.info("Dashboard mounted at /dashboard")
            except Exception as exc:
                logger.warning("Could not mount dashboard: %s", exc)

        logger.info(
            "GhostGuard started — policy=%s upstream=%s dashboard=%s",
            policy_name,
            state["upstream_url"],
            state["dashboard_enabled"],
        )

        yield

        # --- Shutdown ---
        await upstream.close()
        await audit_store.close()
        logger.info("GhostGuard shut down cleanly")

    app = FastAPI(
        title="GhostGuard",
        description="AI Agent Security Proxy",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Middleware (order matters: outermost first)
    app.add_middleware(TimingMiddleware)
    app.add_middleware(RequestIdMiddleware)
    setup_cors(app)

    # Routes
    app.include_router(router)

    return app
