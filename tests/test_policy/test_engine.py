"""Tests for the PolicyEngine evaluation pipeline.

These tests exercise the real PolicyEngine against the test policy
defined in conftest.py -- no mocking of core logic.
"""

from __future__ import annotations

from ghostguard._types import ToolCall, Verdict
from ghostguard.policy.engine import PolicyEngine

# ------------------------------------------------------------------
# Tier 1: Static rule evaluation
# ------------------------------------------------------------------


class TestStaticRules:
    """Tier 1 -- tool name matching and argument constraints."""

    def test_allow_safe_read(self, policy_engine: PolicyEngine) -> None:
        """read_file within /workspace should be ALLOW."""
        decision = policy_engine.evaluate(
            tool_name="read_file",
            arguments={"path": "/workspace/src/app.py"},
        )
        assert decision.verdict == Verdict.ALLOW
        assert decision.tier == "static"

    def test_deny_sensitive_file(self, policy_engine: PolicyEngine) -> None:
        """read_file targeting a .env file should be DENY (blocklist_patterns)."""
        decision = policy_engine.evaluate(
            tool_name="read_file",
            arguments={"path": "/workspace/config/.env"},
        )
        assert decision.verdict == Verdict.DENY

    def test_deny_blocklisted_path(self, policy_engine: PolicyEngine) -> None:
        """read_file on /etc/passwd should be DENY (exact blocklist)."""
        decision = policy_engine.evaluate(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
        )
        assert decision.verdict == Verdict.DENY

    def test_deny_shell(self, policy_engine: PolicyEngine) -> None:
        """execute_command is unconditionally denied."""
        decision = policy_engine.evaluate(
            tool_name="execute_command",
            arguments={"command": "echo hello"},
        )
        assert decision.verdict == Verdict.DENY
        assert decision.tier == "static"

    def test_deny_unknown_tool(self, policy_engine: PolicyEngine) -> None:
        """A tool not listed in the policy matches the '*' catch-all -> DENY."""
        decision = policy_engine.evaluate(
            tool_name="random_never_heard_of_tool",
            arguments={},
        )
        assert decision.verdict == Verdict.DENY

    def test_sandbox_python(self, policy_engine: PolicyEngine) -> None:
        """run_python with safe code should be SANDBOX (not deny)."""
        decision = policy_engine.evaluate(
            tool_name="run_python",
            arguments={"code": "print('hello world')"},
        )
        assert decision.verdict == Verdict.SANDBOX

    def test_deny_path_pattern_mismatch(self, policy_engine: PolicyEngine) -> None:
        """read_file outside /workspace fails the pattern constraint -> DENY."""
        decision = policy_engine.evaluate(
            tool_name="read_file",
            arguments={"path": "/var/log/syslog"},
        )
        assert decision.verdict == Verdict.DENY


# ------------------------------------------------------------------
# Tier 2: Pattern matching (injection detection)
# ------------------------------------------------------------------


class TestPatternMatching:
    """Tier 2 -- global regex patterns across all argument values."""

    def test_path_traversal_detection(self, policy_engine: PolicyEngine) -> None:
        """Path traversal sequences should be caught (Tier 1 or Tier 2)."""
        decision = policy_engine.evaluate(
            tool_name="read_file",
            arguments={"path": "/workspace/../../../etc/passwd"},
        )
        assert decision.verdict == Verdict.DENY
        # May be caught by static blocklist_patterns (Tier 1) or global
        # pattern rules (Tier 2) -- either is correct.  The reason will
        # reference either the literal ".." or the escaped regex "\.\./".
        reason_lower = decision.reason.lower()
        assert (
            ".." in decision.reason
            or "\\." in decision.reason
            or "traversal" in reason_lower
            or "blocklist" in reason_lower
        )

    def test_sql_injection_detection(self, policy_engine: PolicyEngine) -> None:
        """SQL DROP TABLE should be caught (static blocklist_patterns on query_database)."""
        decision = policy_engine.evaluate(
            tool_name="query_database",
            arguments={"query": "SELECT * FROM users; DROP TABLE users;"},
        )
        assert decision.verdict == Verdict.DENY

    def test_sql_injection_union_select(self, policy_engine: PolicyEngine) -> None:
        """UNION SELECT injection should be caught by Tier 2 patterns."""
        decision = policy_engine.evaluate(
            tool_name="query_database",
            arguments={"query": "SELECT id FROM users UNION SELECT password FROM admins"},
        )
        assert decision.verdict == Verdict.DENY

    def test_command_injection_semicolon(self, policy_engine: PolicyEngine) -> None:
        """Semicolon-based command injection should be caught."""
        decision = policy_engine.evaluate(
            tool_name="write_file",
            arguments={"path": "/workspace/test.txt", "content": "hello; rm -rf /"},
        )
        assert decision.verdict == Verdict.DENY

    def test_clean_values_pass_patterns(self, policy_engine: PolicyEngine) -> None:
        """Normal argument values should not trigger pattern rules."""
        decision = policy_engine.evaluate(
            tool_name="write_file",
            arguments={"path": "/workspace/readme.txt", "content": "Hello, world!"},
        )
        assert decision.verdict == Verdict.ALLOW


# ------------------------------------------------------------------
# Tier 3: Anomaly detection (rate limiting)
# ------------------------------------------------------------------


class TestRateLimiting:
    """Tier 3 -- sliding-window rate limits and burst detection."""

    def test_rate_limiting_burst(self, policy_engine: PolicyEngine) -> None:
        """Rapid calls to the same tool should trigger burst detection -> DENY.

        The test policy sets burst_max=3 within a 2-second window.
        """
        session = "test-burst-session"
        # Reset to ensure a clean slate
        policy_engine.reset_counters(session)

        denied = False
        for i in range(10):
            decision = policy_engine.evaluate(
                tool_name="read_file",
                arguments={"path": "/workspace/file.txt"},
                session_id=session,
            )
            reason = decision.reason.lower()
            if decision.verdict == Verdict.DENY and ("rate" in reason or "burst" in reason):
                denied = True
                break

        assert denied, "Expected a DENY from rate-limit / burst detection after rapid calls"

    def test_separate_sessions_isolated(self, policy_engine: PolicyEngine) -> None:
        """Rate-limit counters should be isolated per session."""
        session_a = "session-a-isolated"
        session_b = "session-b-isolated"
        policy_engine.reset_counters(session_a)
        policy_engine.reset_counters(session_b)

        # Load session A
        for _ in range(4):
            policy_engine.evaluate(
                tool_name="read_file",
                arguments={"path": "/workspace/f.txt"},
                session_id=session_a,
            )

        # Session B should still be clean
        decision_b = policy_engine.evaluate(
            tool_name="read_file",
            arguments={"path": "/workspace/f.txt"},
            session_id=session_b,
        )
        assert decision_b.verdict != Verdict.DENY or "rate" not in decision_b.reason.lower()


# ------------------------------------------------------------------
# Python sandbox argument checks
# ------------------------------------------------------------------


class TestPythonSandbox:
    """Argument constraint checks specific to run_python."""

    def test_python_sandbox_import_os(self, policy_engine: PolicyEngine) -> None:
        """run_python with 'import os' should be DENY (blocklist_patterns on code)."""
        decision = policy_engine.evaluate(
            tool_name="run_python",
            arguments={"code": "import os\nos.system('whoami')"},
        )
        assert decision.verdict == Verdict.DENY

    def test_python_sandbox_subprocess(self, policy_engine: PolicyEngine) -> None:
        """run_python with 'subprocess' should be DENY."""
        decision = policy_engine.evaluate(
            tool_name="run_python",
            arguments={"code": "import subprocess\nsubprocess.run(['ls'])"},
        )
        assert decision.verdict == Verdict.DENY

    def test_python_sandbox_safe_code(self, policy_engine: PolicyEngine) -> None:
        """run_python with safe code should be SANDBOX (not deny)."""
        decision = policy_engine.evaluate(
            tool_name="run_python",
            arguments={"code": "result = sum(range(100))\nprint(result)"},
        )
        assert decision.verdict == Verdict.SANDBOX


# ------------------------------------------------------------------
# ToolCall object interface
# ------------------------------------------------------------------


class TestToolCallInterface:
    """Ensure the engine works with ToolCall objects as well as kwargs."""

    def test_evaluate_with_tool_call_object(
        self, policy_engine: PolicyEngine, sample_tool_call: ToolCall
    ) -> None:
        """Passing a ToolCall directly should work the same as kwargs."""
        decision = policy_engine.evaluate(sample_tool_call)
        assert decision.verdict == Verdict.ALLOW

    def test_evaluate_with_denied_tool_call_object(
        self, policy_engine: PolicyEngine, denied_tool_call: ToolCall
    ) -> None:
        """Passing a denied ToolCall should return DENY."""
        decision = policy_engine.evaluate(denied_tool_call)
        assert decision.verdict == Verdict.DENY

    def test_decision_has_latency(self, policy_engine: PolicyEngine) -> None:
        """Every decision should have a non-negative latency_ms."""
        decision = policy_engine.evaluate(
            tool_name="read_file", arguments={"path": "/workspace/x.py"}
        )
        assert decision.latency_ms >= 0.0

    def test_decision_has_tier(self, policy_engine: PolicyEngine) -> None:
        """Every decision should report which tier produced the verdict."""
        decision = policy_engine.evaluate(tool_name="execute_command", arguments={})
        assert decision.tier in {"static", "pattern", "anomaly", "default"}
