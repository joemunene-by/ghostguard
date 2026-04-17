"""SQLite schema and data model for GhostGuard audit events.

Every tool-call evaluation — whether allowed, denied, or sandboxed — is
recorded as an ``AuditEvent`` for compliance, debugging, and analytics.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    request_id      TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    arguments       TEXT NOT NULL DEFAULT '{}',
    verdict         TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    tier            TEXT NOT NULL DEFAULT 'unknown',
    latency_ms      REAL NOT NULL DEFAULT 0.0,
    upstream_model  TEXT NOT NULL DEFAULT '',
    policy_version  TEXT NOT NULL DEFAULT ''
);
"""

CREATE_INDEXES_SQL = """\
CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_session     ON audit_events (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_tool_name   ON audit_events (tool_name);
CREATE INDEX IF NOT EXISTS idx_audit_verdict     ON audit_events (verdict);
"""


@dataclass
class AuditEvent:
    """A single audit record for a tool-call evaluation."""

    session_id: str
    request_id: str
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    verdict: str = "allow"
    reason: str = ""
    tier: str = "unknown"
    latency_ms: float = 0.0
    upstream_model: str = ""
    policy_version: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_row(self) -> tuple[Any, ...]:
        """Convert to a tuple suitable for an INSERT statement."""
        return (
            self.id,
            self.timestamp,
            self.session_id,
            self.request_id,
            self.tool_name,
            json.dumps(self.arguments),
            self.verdict,
            self.reason,
            self.tier,
            self.latency_ms,
            self.upstream_model,
            self.policy_version,
        )

    @classmethod
    def from_row(cls, row: tuple[Any, ...] | dict[str, Any]) -> AuditEvent:
        """Reconstruct an AuditEvent from a database row.

        Accepts either a tuple (positional) or a dict (from
        ``sqlite3.Row``).
        """
        if isinstance(row, dict):
            args = row.get("arguments", "{}")
            return cls(
                id=row["id"],
                timestamp=row["timestamp"],
                session_id=row["session_id"],
                request_id=row["request_id"],
                tool_name=row["tool_name"],
                arguments=json.loads(args) if isinstance(args, str) else args,
                verdict=row["verdict"],
                reason=row["reason"],
                tier=row["tier"],
                latency_ms=row["latency_ms"],
                upstream_model=row["upstream_model"],
                policy_version=row["policy_version"],
            )
        # Tuple / sequence form
        return cls(
            id=row[0],
            timestamp=row[1],
            session_id=row[2],
            request_id=row[3],
            tool_name=row[4],
            arguments=json.loads(row[5]) if isinstance(row[5], str) else row[5],
            verdict=row[6],
            reason=row[7],
            tier=row[8],
            latency_ms=row[9],
            upstream_model=row[10],
            policy_version=row[11],
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary (JSON-safe)."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "verdict": self.verdict,
            "reason": self.reason,
            "tier": self.tier,
            "latency_ms": self.latency_ms,
            "upstream_model": self.upstream_model,
            "policy_version": self.policy_version,
        }
