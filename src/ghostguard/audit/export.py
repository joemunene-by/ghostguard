"""Export audit events to JSONL and CSV formats.

Both functions accept a list of ``AuditEvent`` objects and write them
to the specified file path.  They run synchronously but are designed to
be called from async code via ``asyncio.to_thread`` if needed.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ghostguard.audit.models import AuditEvent

# Column order for CSV export
_CSV_COLUMNS = [
    "id",
    "timestamp",
    "session_id",
    "request_id",
    "tool_name",
    "arguments",
    "verdict",
    "reason",
    "tier",
    "latency_ms",
    "upstream_model",
    "policy_version",
]


def export_jsonl(events: list[AuditEvent], file_path: str | Path) -> int:
    """Write audit events as newline-delimited JSON (JSON Lines).

    Parameters
    ----------
    events:
        The audit events to export.
    file_path:
        Destination file path.

    Returns
    -------
    int
        Number of events written.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event.to_dict(), default=str) + "\n")
            count += 1

    return count


def export_csv(events: list[AuditEvent], file_path: str | Path) -> int:
    """Write audit events as a CSV file.

    Parameters
    ----------
    events:
        The audit events to export.
    file_path:
        Destination file path.

    Returns
    -------
    int
        Number of events written.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for event in events:
            row = event.to_dict()
            # Serialise arguments dict to JSON string for CSV
            row["arguments"] = json.dumps(row["arguments"], default=str)
            writer.writerow(row)
            count += 1

    return count
