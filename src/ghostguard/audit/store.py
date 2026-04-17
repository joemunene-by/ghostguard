"""Async audit store backed by SQLite (via aiosqlite).

Provides insert, query, and aggregation methods for audit events.
Uses WAL mode for concurrent read/write performance.
"""

from __future__ import annotations

import logging
from typing import Any

import aiosqlite

from ghostguard.audit.models import (
    CREATE_INDEXES_SQL,
    CREATE_TABLE_SQL,
    AuditEvent,
)

logger = logging.getLogger(__name__)

INSERT_SQL = """\
INSERT INTO audit_events (
    id, timestamp, session_id, request_id, tool_name, arguments,
    verdict, reason, tier, latency_ms, upstream_model, policy_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class AuditStore:
    """Async SQLite audit store.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite database file.
    """

    def __init__(self, db_path: str = "ghostguard.db") -> None:
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Open the database, create tables, and enable WAL mode."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA busy_timeout=5000")
        await self._db.executescript(CREATE_TABLE_SQL + CREATE_INDEXES_SQL)
        await self._db.commit()
        logger.info("Audit store initialised at %s", self.db_path)

    async def _ensure_db(self) -> aiosqlite.Connection:
        if self._db is None:
            await self.initialize()
        assert self._db is not None
        return self._db

    async def log(self, event: AuditEvent) -> None:
        """Insert a single audit event."""
        db = await self._ensure_db()
        await db.execute(INSERT_SQL, event.to_row())
        await db.commit()

    async def query(
        self,
        limit: int = 50,
        offset: int = 0,
        tool_name: str | None = None,
        verdict: str | None = None,
        session_id: str | None = None,
    ) -> list[AuditEvent]:
        """Query audit events with optional filters.

        Parameters
        ----------
        limit:
            Maximum number of events to return.
        offset:
            Number of events to skip (for pagination).
        tool_name:
            Filter by tool name (exact match).
        verdict:
            Filter by verdict (allow/deny/sandbox).
        session_id:
            Filter by session identifier.

        Returns
        -------
        list[AuditEvent]
            Events ordered by timestamp descending.
        """
        db = await self._ensure_db()

        conditions: list[str] = []
        params: list[Any] = []

        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        sql = f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = await db.execute(sql, params)
        rows = await cursor.fetchall()
        return [AuditEvent.from_row(dict(row)) for row in rows]

    async def stats(self) -> dict[str, Any]:
        """Aggregate statistics for the dashboard.

        Returns
        -------
        dict
            Keys: ``total``, ``by_verdict``, ``top_blocked_tools``,
            ``events_per_hour``.
        """
        db = await self._ensure_db()

        # Total count
        cursor = await db.execute("SELECT COUNT(*) FROM audit_events")
        row = await cursor.fetchone()
        total = row[0] if row else 0

        # Counts by verdict
        cursor = await db.execute(
            "SELECT verdict, COUNT(*) as cnt FROM audit_events GROUP BY verdict"
        )
        by_verdict = {r["verdict"]: r["cnt"] for r in await cursor.fetchall()}

        # Top blocked tools
        cursor = await db.execute(
            "SELECT tool_name, COUNT(*) as cnt FROM audit_events "
            "WHERE verdict = 'deny' GROUP BY tool_name "
            "ORDER BY cnt DESC LIMIT 10"
        )
        top_blocked = [
            {"tool": r["tool_name"], "count": r["cnt"]}
            for r in await cursor.fetchall()
        ]

        # Events per hour (last 24h)
        cursor = await db.execute(
            "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, "
            "COUNT(*) as cnt "
            "FROM audit_events "
            "WHERE timestamp >= datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour"
        )
        events_per_hour = [
            {"hour": r["hour"], "count": r["cnt"]}
            for r in await cursor.fetchall()
        ]

        return {
            "total": total,
            "by_verdict": by_verdict,
            "top_blocked_tools": top_blocked,
            "events_per_hour": events_per_hour,
        }

    async def count(self) -> int:
        """Return the total number of audit events."""
        db = await self._ensure_db()
        cursor = await db.execute("SELECT COUNT(*) FROM audit_events")
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None
            logger.info("Audit store closed")
