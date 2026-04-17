"""Tier 2 — Global pattern matching.

Scans *all* argument values (recursively, including nested dicts and lists)
against a set of pre-compiled regex patterns.  Designed to catch injection
attacks regardless of which tool is being called.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from ghostguard._types import Decision, ToolCall, Verdict
from ghostguard.policy.schema import PatternRule, PolicyConfig

logger = logging.getLogger(__name__)


class PatternEvaluator:
    """Tier 2 evaluator: pre-compiled global pattern scanning.

    The evaluator compiles all patterns once at construction time (or when
    a new policy is swapped in) so that per-request overhead is minimal.
    """

    TIER = "pattern"

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self._compiled: list[tuple[PatternRule, re.Pattern[str]]] = []
        if policy is not None:
            self.load_patterns(policy)

    # ── Pattern management ──────────────────────────────────────────

    def load_patterns(self, policy: PolicyConfig) -> None:
        """(Re-)compile the patterns from *policy*."""
        compiled: list[tuple[PatternRule, re.Pattern[str]]] = []
        for rule in policy.patterns:
            try:
                compiled.append((rule, re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)))
            except re.error as exc:
                logger.warning("Skipping invalid pattern '%s' (%s): %s", rule.name, rule.pattern, exc)
        self._compiled = compiled

    # ── Public API ──────────────────────────────────────────────────

    def evaluate(self, tool_call: ToolCall, policy: PolicyConfig) -> Decision | None:
        """Scan every argument value against the global patterns.

        Returns a DENY :class:`Decision` on the first match, or ``None``
        if nothing triggered.
        """
        # Lazily load patterns if not yet compiled (e.g. evaluator was
        # constructed without a policy reference).
        if not self._compiled and policy.patterns:
            self.load_patterns(policy)

        # Collect all string leaves from the arguments.
        leaves = list(self._extract_strings(tool_call.arguments))

        for rule, regex in self._compiled:
            for text in leaves:
                if regex.search(text):
                    verdict = self._action_to_verdict(rule.action)
                    return Decision(
                        verdict=verdict,
                        reason=rule.reason or f"Pattern '{rule.name}' matched.",
                        tier=self.TIER,
                        tool_call=tool_call,
                    )

        return None

    # ── Recursive string extraction ─────────────────────────────────

    @staticmethod
    def _extract_strings(obj: Any) -> list[str]:
        """Recursively yield all string values from a nested structure."""
        results: list[str] = []
        stack: list[Any] = [obj]
        while stack:
            current = stack.pop()
            if isinstance(current, str):
                results.append(current)
            elif isinstance(current, dict):
                stack.extend(current.values())
            elif isinstance(current, (list, tuple)):
                stack.extend(current)
            else:
                # Coerce scalars so we don't miss e.g. integers that look
                # like port numbers embedded in an SSRF check.
                results.append(str(current))
        return results

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _action_to_verdict(action: str) -> Verdict:
        mapping = {
            "allow": Verdict.ALLOW,
            "deny": Verdict.DENY,
            "sandbox": Verdict.SANDBOX,
            "prompt": Verdict.PENDING,
        }
        return mapping.get(action, Verdict.DENY)
