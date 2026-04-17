"""Tests for ToolCallInterceptor.

These tests exercise the real interceptor with a real PolicyEngine --
no mocking of the core evaluation logic. The audit store uses an
in-memory SQLite database.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from ghostguard._types import ToolCallFormat
from ghostguard.audit.store import AuditStore
from ghostguard.policy.engine import PolicyEngine
from ghostguard.proxy.interceptor import ToolCallInterceptor

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture()
async def audit_store(tmp_path: Path) -> AuditStore:
    """Create an in-memory audit store for testing."""
    store = AuditStore(str(tmp_path / "test_audit.db"))
    await store.initialize()
    yield store  # type: ignore[misc]
    await store.close()


@pytest.fixture()
def interceptor(policy_engine: PolicyEngine, audit_store: AuditStore) -> ToolCallInterceptor:
    """Create an interceptor wired to the real policy engine."""
    return ToolCallInterceptor(policy_engine, audit_store)


# ------------------------------------------------------------------
# Helper builders for LLM responses
# ------------------------------------------------------------------


def _openai_response(tool_calls: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a minimal OpenAI chat completion response with tool calls."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": tool_calls,
                },
                "finish_reason": "tool_calls",
            }
        ],
    }


def _openai_tool_call(tc_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a single OpenAI-format tool call."""
    return {
        "id": tc_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": json.dumps(arguments),
        },
    }


def _anthropic_response(content_blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a minimal Anthropic messages response."""
    return {
        "id": "msg-test",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-20250514",
        "content": content_blocks,
        "stop_reason": "tool_use",
    }


def _anthropic_tool_use(tc_id: str, name: str, input_data: dict[str, Any]) -> dict[str, Any]:
    """Build a single Anthropic tool_use content block."""
    return {
        "type": "tool_use",
        "id": tc_id,
        "name": name,
        "input": input_data,
    }


# ------------------------------------------------------------------
# OpenAI format tests
# ------------------------------------------------------------------


class TestOpenAIFormat:
    """Tests using OpenAI wire format."""

    @pytest.mark.asyncio
    async def test_openai_format_allow(self, interceptor: ToolCallInterceptor) -> None:
        """A safe read_file tool call should pass through unchanged."""
        tc = _openai_tool_call("call_001", "read_file", {"path": "/workspace/main.py"})
        response = _openai_response([tc])

        result = await interceptor.intercept(response, session_id="s1", request_id="r1")

        # The tool call should still be present
        tool_calls = result["choices"][0]["message"].get("tool_calls", [])
        assert len(tool_calls) == 1
        assert tool_calls[0]["id"] == "call_001"
        # finish_reason should remain tool_calls
        assert result["choices"][0]["finish_reason"] == "tool_calls"

    @pytest.mark.asyncio
    async def test_openai_format_deny(self, interceptor: ToolCallInterceptor) -> None:
        """An execute_command tool call should be stripped and denial added."""
        tc = _openai_tool_call("call_002", "execute_command", {"command": "rm -rf /"})
        response = _openai_response([tc])

        result = await interceptor.intercept(response, session_id="s2", request_id="r2")

        # The tool call should be removed
        message = result["choices"][0]["message"]
        assert "tool_calls" not in message

        # A denial explanation should be in the content
        content = message.get("content", "")
        assert "[GhostGuard]" in content
        assert "execute_command" in content

        # finish_reason should revert to "stop"
        assert result["choices"][0]["finish_reason"] == "stop"

    @pytest.mark.asyncio
    async def test_openai_no_tool_calls_passthrough(self, interceptor: ToolCallInterceptor) -> None:
        """A response with no tool calls should pass through untouched."""
        response = {
            "id": "chatcmpl-text",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello, world!",
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        original = copy.deepcopy(response)
        result = await interceptor.intercept(response, session_id="s3", request_id="r3")
        assert result == original


# ------------------------------------------------------------------
# Anthropic format tests
# ------------------------------------------------------------------


class TestAnthropicFormat:
    """Tests using Anthropic wire format."""

    @pytest.mark.asyncio
    async def test_anthropic_format_allow(self, interceptor: ToolCallInterceptor) -> None:
        """A safe tool_use block should be preserved."""
        block = _anthropic_tool_use("tu_001", "read_file", {"path": "/workspace/notes.txt"})
        response = _anthropic_response([block])

        result = await interceptor.intercept(response, session_id="s4", request_id="r4")

        tool_blocks = [b for b in result["content"] if b.get("type") == "tool_use"]
        assert len(tool_blocks) == 1
        assert tool_blocks[0]["name"] == "read_file"
        assert result["stop_reason"] == "tool_use"

    @pytest.mark.asyncio
    async def test_anthropic_format_deny(self, interceptor: ToolCallInterceptor) -> None:
        """A denied tool_use block should be removed and text block added."""
        block = _anthropic_tool_use("tu_002", "execute_command", {"command": "whoami"})
        response = _anthropic_response([block])

        result = await interceptor.intercept(response, session_id="s5", request_id="r5")

        # No tool_use blocks should remain
        tool_blocks = [b for b in result["content"] if b.get("type") == "tool_use"]
        assert len(tool_blocks) == 0

        # A text block with the denial should be present
        text_blocks = [b for b in result["content"] if b.get("type") == "text"]
        assert len(text_blocks) >= 1
        denial_text = text_blocks[-1]["text"]
        assert "[GhostGuard]" in denial_text
        assert "execute_command" in denial_text

        # stop_reason should flip to end_turn
        assert result["stop_reason"] == "end_turn"


# ------------------------------------------------------------------
# Mixed decisions
# ------------------------------------------------------------------


class TestMixedDecisions:
    """Responses with multiple tool calls, some allowed and some denied."""

    @pytest.mark.asyncio
    async def test_openai_mixed_decisions(self, interceptor: ToolCallInterceptor) -> None:
        """One allowed + one denied tool call in the same response."""
        safe_tc = _openai_tool_call("call_safe", "read_file", {"path": "/workspace/data.json"})
        bad_tc = _openai_tool_call("call_bad", "execute_command", {"command": "cat /etc/shadow"})
        response = _openai_response([safe_tc, bad_tc])

        result = await interceptor.intercept(response, session_id="s6", request_id="r6")

        # Only the safe call should survive
        remaining = result["choices"][0]["message"].get("tool_calls", [])
        assert len(remaining) == 1
        assert remaining[0]["id"] == "call_safe"

        # Denial content should reference the bad call
        content = result["choices"][0]["message"].get("content", "")
        assert "execute_command" in content

    @pytest.mark.asyncio
    async def test_anthropic_mixed_decisions(self, interceptor: ToolCallInterceptor) -> None:
        """One allowed + one denied tool_use block in the same response."""
        safe_block = _anthropic_tool_use("tu_safe", "read_file", {"path": "/workspace/readme.md"})
        bad_block = _anthropic_tool_use("tu_bad", "run_shell", {"command": "ls"})
        response = _anthropic_response([safe_block, bad_block])

        result = await interceptor.intercept(response, session_id="s7", request_id="r7")

        tool_blocks = [b for b in result["content"] if b.get("type") == "tool_use"]
        text_blocks = [b for b in result["content"] if b.get("type") == "text"]

        # Safe call kept, bad call removed
        assert len(tool_blocks) == 1
        assert tool_blocks[0]["name"] == "read_file"

        # Denial explanation added
        assert any("[GhostGuard]" in b["text"] for b in text_blocks)

    @pytest.mark.asyncio
    async def test_all_denied_openai(self, interceptor: ToolCallInterceptor) -> None:
        """When all tool calls are denied, finish_reason should be 'stop'."""
        tc1 = _openai_tool_call("c1", "execute_command", {"command": "whoami"})
        tc2 = _openai_tool_call("c2", "run_shell", {"command": "id"})
        response = _openai_response([tc1, tc2])

        result = await interceptor.intercept(response, session_id="s8", request_id="r8")

        message = result["choices"][0]["message"]
        assert "tool_calls" not in message
        assert result["choices"][0]["finish_reason"] == "stop"
        assert "[GhostGuard]" in message.get("content", "")


# ------------------------------------------------------------------
# Format detection
# ------------------------------------------------------------------


class TestFormatDetection:
    """Test the static format detection helper."""

    def test_detect_openai(self) -> None:
        response = {"choices": [{"message": {"content": "hi"}}]}
        fmt = ToolCallInterceptor.detect_format(response)
        assert fmt == ToolCallFormat.OPENAI

    def test_detect_anthropic(self) -> None:
        response = {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
        }
        fmt = ToolCallInterceptor.detect_format(response)
        assert fmt == ToolCallFormat.ANTHROPIC

    def test_detect_unknown(self) -> None:
        response = {"data": "something else entirely"}
        fmt = ToolCallInterceptor.detect_format(response)
        assert fmt == ToolCallFormat.UNKNOWN


# ------------------------------------------------------------------
# Audit trail
# ------------------------------------------------------------------


class TestAuditTrail:
    """Ensure interceptor logs decisions to the audit store."""

    @pytest.mark.asyncio
    async def test_decisions_logged(
        self, interceptor: ToolCallInterceptor, audit_store: AuditStore
    ) -> None:
        """Every evaluated tool call should produce an audit event."""
        tc = _openai_tool_call("c_audit", "execute_command", {"command": "x"})
        response = _openai_response([tc])

        await interceptor.intercept(response, session_id="audit-s", request_id="audit-r")

        events = await audit_store.query(limit=10, session_id="audit-s")
        assert len(events) >= 1
        assert events[0].tool_name == "execute_command"
        assert events[0].verdict == "deny"
