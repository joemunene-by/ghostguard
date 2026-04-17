"""Shared test fixtures for GhostGuard."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ghostguard._types import ToolCall, ToolCallFormat
from ghostguard.policy.engine import PolicyEngine

# ---------------------------------------------------------------------------
# Test policy YAML
# ---------------------------------------------------------------------------

_TEST_POLICY_YAML = textwrap.dedent("""\
    version: "1"

    metadata:
      name: "Test Policy"
      description: "Policy used in the GhostGuard test suite"

    defaults:
      action: deny
      log_level: warning

    rate_limits:
      global_per_minute: 30
      per_tool_per_minute: 5
      burst_window_seconds: 2
      burst_max: 3

    anomaly:
      enabled: true
      window_seconds: 10
      threshold: 15
      burst_window_seconds: 2
      burst_max: 3

    tools:
      - name: read_file
        action: allow
        reason: "File reading permitted within workspace"
        constraints:
          path:
            pattern: "^/workspace/.*"
            blocklist:
              - "/etc/passwd"
              - "/etc/shadow"
            blocklist_patterns:
              - "\\\\.\\\\./"
              - "/\\\\.env$"
            max_length: 4096

      - name: write_file
        action: allow
        reason: "File writing permitted within workspace"
        constraints:
          path:
            pattern: "^/workspace/.*"

      - name: execute_command
        action: deny
        reason: "Shell command execution is not permitted"

      - name: run_shell
        action: deny
        reason: "Shell access is not permitted"

      - name: run_python
        action: sandbox
        reason: "Python execution is sandboxed"
        constraints:
          code:
            blocklist_patterns:
              - "\\\\bimport\\\\s+os\\\\b"
              - "\\\\bsubprocess\\\\b"
              - "\\\\bos\\\\.system\\\\b"
            max_length: 65536

      - name: query_database
        action: sandbox
        reason: "Database queries run read-only"
        constraints:
          query:
            blocklist_patterns:
              - "\\\\bDROP\\\\b"
              - "\\\\bDELETE\\\\b"
              - "\\\\bINSERT\\\\b"
              - "\\\\bUPDATE\\\\b"

      - name: "*"
        action: deny
        reason: "Unknown tool denied by default"

    patterns:
      - name: path_traversal
        pattern: "(\\\\.\\\\.[\\\\/]){1,}"
        action: deny
        reason: "Path traversal detected"
        severity: critical

      - name: sql_injection_union
        pattern: "(?i)\\\\bunion\\\\b.*\\\\bselect\\\\b"
        action: deny
        reason: "Potential SQL injection (UNION SELECT)"
        severity: high

      - name: command_injection_semicolon
        pattern: ";\\\\s*(rm|cat|curl|wget|bash|sh|python|perl)\\\\b"
        action: deny
        reason: "Potential command injection via semicolon"
        severity: critical
""")


@pytest.fixture()
def sample_policy_path(tmp_path: Path) -> Path:
    """Write the test YAML policy to a temporary file and return its path."""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(_TEST_POLICY_YAML, encoding="utf-8")
    return policy_file


@pytest.fixture()
def policy_engine(sample_policy_path: Path) -> PolicyEngine:
    """Return a PolicyEngine loaded from the test policy."""
    return PolicyEngine.from_yaml(sample_policy_path)


@pytest.fixture()
def sample_tool_call() -> ToolCall:
    """A safe read_file tool call within the workspace."""
    return ToolCall(
        id="tc_safe_read_001",
        name="read_file",
        arguments={"path": "/workspace/src/main.py"},
        format=ToolCallFormat.OPENAI,
    )


@pytest.fixture()
def denied_tool_call() -> ToolCall:
    """A tool call that should always be denied (execute_command)."""
    return ToolCall(
        id="tc_deny_exec_001",
        name="execute_command",
        arguments={"command": "ls -la"},
        format=ToolCallFormat.OPENAI,
    )
