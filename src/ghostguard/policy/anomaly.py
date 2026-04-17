"""Tier 3 — Anomaly detection via sliding-window rate limiting.

Tracks per-tool and global call rates using in-memory sliding windows
(one :class:`collections.deque` per counter).  No external dependencies
are required — this tier is designed to be fast and self-contained.
"""

from __future__ import annotations

import collections
import logging
import time

from ghostguard._types import Decision, ToolCall, Verdict
from ghostguard.policy.schema import PolicyConfig

logger = logging.getLogger(__name__)


class _SlidingWindow:
    """Fixed-duration sliding window backed by a deque of timestamps."""

    __slots__ = ("_window_seconds", "_timestamps")

    def __init__(self, window_seconds: int) -> None:
        self._window_seconds = window_seconds
        self._timestamps: collections.deque[float] = collections.deque()

    def record(self, now: float | None = None) -> None:
        """Record a new event at *now* (defaults to current time)."""
        ts = now if now is not None else time.monotonic()
        self._timestamps.append(ts)
        self._evict(ts)

    def count(self, now: float | None = None) -> int:
        """Return the number of events inside the current window."""
        ts = now if now is not None else time.monotonic()
        self._evict(ts)
        return len(self._timestamps)

    def _evict(self, now: float) -> None:
        cutoff = now - self._window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


class AnomalyDetector:
    """Tier 3 evaluator: rate-limit and burst detection.

    Counters are keyed by ``(session_id, scope)`` where *scope* is either
    the literal ``"__global__"`` or the tool name.  This keeps sessions
    isolated while still allowing a single global cap.
    """

    TIER = "anomaly"

    def __init__(self) -> None:
        # { (session_id, scope): _SlidingWindow }
        self._rate_windows: dict[tuple[str, str], _SlidingWindow] = {}
        self._burst_windows: dict[tuple[str, str], _SlidingWindow] = {}

    # ── Public API ──────────────────────────────────────────────────

    def evaluate(
        self,
        tool_call: ToolCall,
        policy: PolicyConfig,
        session_id: str = "default",
    ) -> Decision | None:
        """Check rate limits and burst thresholds.

        Returns a DENY :class:`Decision` if a limit is exceeded, or
        ``None`` to defer to the next tier.
        """
        if not policy.anomaly.enabled:
            return None

        now = time.monotonic()

        # ── Global rate check ───────────────────────────────────────
        global_key = (session_id, "__global__")
        global_window = self._get_or_create_rate_window(
            global_key,
            policy.rate_limits.global_per_minute if policy.rate_limits else 60,
        )
        global_window.record(now)
        if global_window.count(now) > policy.rate_limits.global_per_minute:
            return self._deny(
                f"Global rate limit exceeded ({policy.rate_limits.global_per_minute}/min).",
                tool_call,
            )

        # ── Per-tool rate check ─────────────────────────────────────
        tool_key = (session_id, tool_call.name)
        tool_window = self._get_or_create_rate_window(
            tool_key,
            60,
        )
        tool_window.record(now)
        if tool_window.count(now) > policy.rate_limits.per_tool_per_minute:
            return self._deny(
                f"Per-tool rate limit exceeded for '{tool_call.name}' "
                f"({policy.rate_limits.per_tool_per_minute}/min).",
                tool_call,
            )

        # ── Burst detection ─────────────────────────────────────────
        burst_key = (session_id, f"__burst__{tool_call.name}")
        burst_window = self._get_or_create_burst_window(
            burst_key,
            policy.anomaly.burst_window_seconds or policy.rate_limits.burst_window_seconds,
        )
        burst_window.record(now)
        burst_max = policy.anomaly.burst_max or policy.rate_limits.burst_max
        if burst_window.count(now) > burst_max:
            return self._deny(
                f"Burst detected for '{tool_call.name}' "
                f"({burst_max} calls in {policy.anomaly.burst_window_seconds}s).",
                tool_call,
            )

        # ── Global anomaly threshold ────────────────────────────────
        anomaly_key = (session_id, "__anomaly__")
        anomaly_window = self._get_or_create_rate_window(
            anomaly_key,
            policy.anomaly.window_seconds,
        )
        anomaly_window.record(now)
        if anomaly_window.count(now) > policy.anomaly.threshold:
            return self._deny(
                f"Anomaly threshold exceeded ({policy.anomaly.threshold} calls "
                f"in {policy.anomaly.window_seconds}s).",
                tool_call,
            )

        return None

    # ── Window management ───────────────────────────────────────────

    def _get_or_create_rate_window(
        self, key: tuple[str, str], window_seconds: int
    ) -> _SlidingWindow:
        if key not in self._rate_windows:
            self._rate_windows[key] = _SlidingWindow(window_seconds)
        return self._rate_windows[key]

    def _get_or_create_burst_window(
        self, key: tuple[str, str], window_seconds: int
    ) -> _SlidingWindow:
        if key not in self._burst_windows:
            self._burst_windows[key] = _SlidingWindow(window_seconds)
        return self._burst_windows[key]

    def reset(self, session_id: str | None = None) -> None:
        """Clear counters.  If *session_id* is given, only that session's
        counters are dropped; otherwise everything is wiped."""
        if session_id is None:
            self._rate_windows.clear()
            self._burst_windows.clear()
        else:
            self._rate_windows = {k: v for k, v in self._rate_windows.items() if k[0] != session_id}
            self._burst_windows = {
                k: v for k, v in self._burst_windows.items() if k[0] != session_id
            }

    # ── Helpers ─────────────────────────────────────────────────────

    def _deny(self, reason: str, tool_call: ToolCall) -> Decision:
        return Decision(
            verdict=Verdict.DENY,
            reason=reason,
            tier=self.TIER,
            tool_call=tool_call,
        )
