"""WebSocket support for real-time audit event broadcasting.

The ``EventBroadcaster`` manages a set of connected WebSocket clients
and fans out new audit events as they arrive.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class EventBroadcaster:
    """Manages WebSocket subscribers and broadcasts audit events."""

    def __init__(self) -> None:
        self._subscribers: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self, ws: WebSocket) -> None:
        """Accept a WebSocket connection and add it to the subscriber set."""
        await ws.accept()
        async with self._lock:
            self._subscribers.add(ws)
        logger.info("WebSocket client connected (%d total)", len(self._subscribers))

    async def unsubscribe(self, ws: WebSocket) -> None:
        """Remove a WebSocket from the subscriber set."""
        async with self._lock:
            self._subscribers.discard(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._subscribers))

    async def broadcast(self, event_data: dict[str, Any]) -> None:
        """Send an event to all connected WebSocket clients.

        Silently drops connections that have closed.
        """
        if not self._subscribers:
            return

        message = json.dumps(event_data, default=str)
        dead: list[WebSocket] = []

        async with self._lock:
            for ws in self._subscribers:
                try:
                    await ws.send_text(message)
                except Exception:
                    dead.append(ws)

            for ws in dead:
                self._subscribers.discard(ws)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Singleton broadcaster instance shared across the dashboard app
broadcaster = EventBroadcaster()


async def websocket_events(ws: WebSocket) -> None:
    """WebSocket endpoint handler for ``/ws/events``.

    Keeps the connection alive and removes it on disconnect.
    """
    await broadcaster.subscribe(ws)
    try:
        while True:
            # Keep connection alive — client can send pings
            data = await ws.receive_text()
            # Echo pings back as pongs
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.unsubscribe(ws)
