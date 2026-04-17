"""Tier 1 — Static rule evaluation.

Matches the incoming tool call against the explicit tool rules defined in
the policy.  This is the fastest tier: pure dict/glob lookups and regex
checks with no I/O.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from functools import lru_cache

from ghostguard._types import Decision, ToolCall, Verdict
from ghostguard.policy.schema import ArgumentRule, PolicyConfig, ToolRule

logger = logging.getLogger(__name__)


@lru_cache(maxsize=512)
def _compile_re(pattern: str) -> re.Pattern[str]:
    """Compile and cache a regex pattern."""
    return re.compile(pattern, re.DOTALL)


class StaticRuleEvaluator:
    """Tier 1 evaluator: match tool rules by name and validate argument constraints.

    Evaluation logic
    ----------------
    1. Walk the ``tools`` list in order and find the *first* rule whose
       ``name`` matches (glob via :func:`fnmatch.fnmatch`).
    2. If the rule's action is ``deny`` -> return DENY immediately.
    3. If the rule has argument constraints, validate them:
       - ``pattern``: the argument value must *fully* match the regex.
       - ``blocklist``: exact string match against a list of forbidden values.
       - ``blocklist_patterns``: regex *search* against the argument value.
       - ``max_length``: the string length must not exceed the limit.
    4. If a constraint fails -> DENY.
    5. If the action is ``allow`` (and all constraints passed) -> ALLOW.
    6. If the action is ``sandbox`` -> SANDBOX.
    7. If nothing matched, return ``None`` so the next tier can run.
    """

    TIER = "static"

    # ── Public API ──────────────────────────────────────────────────

    def evaluate(self, tool_call: ToolCall, policy: PolicyConfig) -> Decision | None:
        """Evaluate *tool_call* against the static tool rules.

        Returns a :class:`Decision` when a definitive verdict is reached,
        or ``None`` when no rule matched (defer to the next tier).
        """
        rule = self._find_matching_rule(tool_call.name, policy)
        if rule is None:
            return None

        # Immediate deny — no need to inspect arguments.
        if rule.action == "deny":
            return self._decision(
                Verdict.DENY,
                rule.reason or f"Tool '{tool_call.name}' is denied by policy.",
                tool_call,
            )

        # Validate argument constraints (if any).
        if rule.constraints:
            violation = self._check_constraints(tool_call, rule)
            if violation is not None:
                return violation

        # Action mapping.
        if rule.action == "allow":
            return self._decision(
                Verdict.ALLOW,
                rule.reason or f"Tool '{tool_call.name}' is allowed by policy.",
                tool_call,
            )

        if rule.action == "sandbox":
            return self._decision(
                Verdict.SANDBOX,
                rule.reason or f"Tool '{tool_call.name}' must run in a sandbox.",
                tool_call,
            )

        if rule.action == "prompt":
            return self._decision(
                Verdict.PENDING,
                rule.reason or f"Tool '{tool_call.name}' requires human approval.",
                tool_call,
            )

        # Unknown action — treat as deny for safety.
        return self._decision(
            Verdict.DENY,
            f"Unknown action '{rule.action}' in rule for '{tool_call.name}'.",
            tool_call,
        )

    # ── Rule matching ───────────────────────────────────────────────

    @staticmethod
    def _find_matching_rule(tool_name: str, policy: PolicyConfig) -> ToolRule | None:
        """Return the first :class:`ToolRule` whose name matches *tool_name*."""
        for rule in policy.tools:
            if fnmatch.fnmatch(tool_name, rule.name):
                return rule
        return None

    # ── Argument constraint checks ──────────────────────────────────

    def _check_constraints(self, tool_call: ToolCall, rule: ToolRule) -> Decision | None:
        """Validate each argument against its constraints.

        Returns a DENY :class:`Decision` on the first violation, or
        ``None`` if all constraints pass.
        """
        for arg_name, arg_rule in rule.constraints.items():
            value = tool_call.arguments.get(arg_name)
            if value is None:
                # Argument not present — nothing to validate.
                continue

            violation = self._check_single_argument(tool_call, arg_name, value, arg_rule)
            if violation is not None:
                return violation

        return None

    def _check_single_argument(
        self,
        tool_call: ToolCall,
        arg_name: str,
        value: object,
        rule: ArgumentRule,
    ) -> Decision | None:
        str_value = str(value)

        # max_length
        if rule.max_length is not None and len(str_value) > rule.max_length:
            return self._decision(
                Verdict.DENY,
                f"Argument '{arg_name}' exceeds max length ({len(str_value)} > {rule.max_length}).",
                tool_call,
            )

        # blocklist (exact match)
        if rule.blocklist and str_value in rule.blocklist:
            return self._decision(
                Verdict.DENY,
                f"Argument '{arg_name}' value is blocklisted.",
                tool_call,
            )

        # blocklist_patterns (regex search)
        for bp in rule.blocklist_patterns:
            try:
                if _compile_re(bp).search(str_value):
                    return self._decision(
                        Verdict.DENY,
                        f"Argument '{arg_name}' matches blocklist pattern: {bp}",
                        tool_call,
                    )
            except re.error as exc:
                logger.warning("Invalid blocklist_pattern '%s': %s", bp, exc)

        # pattern (full match)
        if rule.pattern is not None:
            try:
                if not _compile_re(rule.pattern).fullmatch(str_value):
                    return self._decision(
                        Verdict.DENY,
                        f"Argument '{arg_name}' does not match required pattern: {rule.pattern}",
                        tool_call,
                    )
            except re.error as exc:
                logger.warning("Invalid pattern '%s': %s", rule.pattern, exc)

        return None

    # ── Helpers ─────────────────────────────────────────────────────

    def _decision(self, verdict: Verdict, reason: str, tool_call: ToolCall) -> Decision:
        return Decision(verdict=verdict, reason=reason, tier=self.TIER, tool_call=tool_call)
