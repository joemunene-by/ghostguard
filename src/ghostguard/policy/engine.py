"""PolicyEngine — the central orchestrator for all evaluation tiers.

Usage::

    from ghostguard import PolicyEngine

    engine = PolicyEngine.from_yaml("policy.yaml")
    decision = engine.evaluate(tool_name="read_file", arguments={"path": "/etc/passwd"})
    print(decision.verdict)  # Verdict.DENY
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from ghostguard._types import Decision, ToolCall, Verdict
from ghostguard.policy.anomaly import AnomalyDetector
from ghostguard.policy.loader import PolicyWatcher
from ghostguard.policy.patterns import PatternEvaluator
from ghostguard.policy.rules import StaticRuleEvaluator
from ghostguard.policy.schema import PolicyConfig

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Orchestrates the multi-tier evaluation pipeline.

    Tiers run in order and short-circuit on the first definitive verdict:

    1. **Static rules** — exact/glob tool matching + argument constraints.
    2. **Pattern scanning** — global regex patterns (injection detection).
    3. **Anomaly detection** — sliding-window rate limits & burst detection.

    If no tier produces a verdict the engine falls back to the policy's
    ``defaults.action``.
    """

    def __init__(
        self,
        policy_path: str | Path | None = None,
        policy: PolicyConfig | None = None,
    ) -> None:
        """Create an engine from a YAML file *or* an already-loaded policy.

        Parameters
        ----------
        policy_path:
            Filesystem path to a YAML policy file.  When provided the
            engine will watch the file and hot-reload on changes.
        policy:
            A pre-built :class:`PolicyConfig`.  Mutually exclusive with
            *policy_path* (if both are given, *policy_path* wins).
        """
        if policy_path is not None:
            self._watcher: PolicyWatcher | None = PolicyWatcher(policy_path)
            self._static_policy: PolicyConfig | None = None
        elif policy is not None:
            self._watcher = None
            self._static_policy = policy
        else:
            # No policy at all — use the defaults (deny-all).
            self._watcher = None
            self._static_policy = PolicyConfig()

        # Instantiate evaluator tiers.
        self._rules = StaticRuleEvaluator()
        self._patterns = PatternEvaluator(self._current_policy)
        self._anomaly = AnomalyDetector()

    # ── Convenience constructors ────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        """Create an engine backed by a YAML policy file."""
        return cls(policy_path=path)

    @classmethod
    def from_policy(cls, policy: PolicyConfig) -> PolicyEngine:
        """Create an engine from a pre-built :class:`PolicyConfig`."""
        return cls(policy=policy)

    # ── Policy access ───────────────────────────────────────────────

    @property
    def _current_policy(self) -> PolicyConfig:
        if self._watcher is not None:
            return self._watcher.policy
        assert self._static_policy is not None
        return self._static_policy

    # ── Core evaluate API ───────────────────────────────────────────

    def evaluate(
        self,
        tool_call: ToolCall | None = None,
        *,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        session_id: str = "default",
    ) -> Decision:
        """Evaluate a tool call against the loaded policy.

        You may pass either a pre-built :class:`ToolCall`, *or* provide
        ``tool_name`` and ``arguments`` as keyword arguments for quick
        inline usage::

            decision = engine.evaluate(tool_name="read_file", arguments={"path": "/etc/passwd"})

        Parameters
        ----------
        tool_call:
            A :class:`ToolCall` instance.  Takes precedence over the
            keyword shortcuts.
        tool_name:
            Shortcut — the tool's name (used when *tool_call* is None).
        arguments:
            Shortcut — the tool's arguments (used when *tool_call* is None).
        session_id:
            Caller-provided session ID for rate-limit isolation.

        Returns
        -------
        Decision
            Always returns a decision; never ``None``.
        """
        # Build or normalise the ToolCall object.
        if tool_call is None:
            if tool_name is None:
                raise ValueError("Either 'tool_call' or 'tool_name' must be provided.")
            tool_call = ToolCall(name=tool_name, arguments=arguments or {})

        # Hot-reload the policy file if it changed on disk.
        if self._watcher is not None:
            if self._watcher.check_and_reload():
                # Re-compile patterns with the fresh policy.
                self._patterns.load_patterns(self._watcher.policy)

        policy = self._current_policy

        t0 = time.perf_counter()

        # ── Tier 1: Static rules ────────────────────────────────────
        #
        # A DENY from static rules is final — no further tiers run.
        # An ALLOW / SANDBOX is *tentative*: Tier 2 (patterns) acts as a
        # global safety net that can still override it to DENY.
        tier1 = self._rules.evaluate(tool_call, policy)
        if tier1 is not None and tier1.verdict == Verdict.DENY:
            tier1.latency_ms = _elapsed_ms(t0)
            return tier1

        # ── Tier 2: Pattern scanning ────────────────────────────────
        #
        # Always runs — patterns catch injection attacks regardless of
        # the tool-level verdict.  A DENY here overrides Tier 1 ALLOW.
        tier2 = self._patterns.evaluate(tool_call, policy)
        if tier2 is not None and tier2.verdict == Verdict.DENY:
            tier2.latency_ms = _elapsed_ms(t0)
            return tier2

        # ── Tier 3: Anomaly detection ───────────────────────────────
        tier3 = self._anomaly.evaluate(tool_call, policy, session_id=session_id)
        if tier3 is not None and tier3.verdict == Verdict.DENY:
            tier3.latency_ms = _elapsed_ms(t0)
            return tier3

        # ── Return the Tier 1 verdict if it was definitive ──────────
        if tier1 is not None and tier1.verdict != Verdict.PENDING:
            tier1.latency_ms = _elapsed_ms(t0)
            return tier1

        # ── Fallback: use the policy default action ─────────────────
        fallback_verdict = _action_to_verdict(policy.defaults.action)
        return Decision(
            verdict=fallback_verdict,
            reason=f"No rule matched; default action is '{policy.defaults.action}'.",
            tier="default",
            latency_ms=_elapsed_ms(t0),
            tool_call=tool_call,
        )

    # ── Anomaly detector management ─────────────────────────────────

    def reset_counters(self, session_id: str | None = None) -> None:
        """Clear rate-limit / anomaly counters."""
        self._anomaly.reset(session_id)


# ── Module-private helpers ──────────────────────────────────────────────


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def _action_to_verdict(action: str) -> Verdict:
    return {
        "allow": Verdict.ALLOW,
        "deny": Verdict.DENY,
        "sandbox": Verdict.SANDBOX,
        "prompt": Verdict.PENDING,
    }.get(action, Verdict.DENY)
