"""Tool-call interceptor — the core innovation of GhostGuard.

Sits between the upstream LLM response and the client, parsing tool calls
from both OpenAI and Anthropic wire formats, evaluating each against the
policy engine, and rewriting the response based on verdicts.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from typing import Any

from ghostguard._types import Decision, ToolCall, ToolCallFormat, Verdict
from ghostguard.audit.models import AuditEvent
from ghostguard.audit.store import AuditStore

logger = logging.getLogger(__name__)


class ToolCallInterceptor:
    """Intercepts LLM responses and evaluates tool calls against policy.

    Parameters
    ----------
    policy_engine:
        The policy engine instance (duck-typed — must have an async
        ``evaluate(tool_call)`` method returning a ``Decision``).
    audit_store:
        Audit store for logging every decision.
    """

    def __init__(self, policy_engine: Any, audit_store: AuditStore) -> None:
        self.policy_engine = policy_engine
        self.audit_store = audit_store
        # Buffer for streaming mode
        self._stream_buffer: dict[str, list[dict[str, Any]]] = {}
        self._stream_decisions: dict[str, list[Decision]] = {}

    async def _evaluate(self, tool_call: ToolCall) -> Decision:
        """Call the policy engine's evaluate method (sync or async)."""
        result = self.policy_engine.evaluate(tool_call)
        if inspect.isawaitable(result):
            return await result
        return result

    def _get_policy_version(self) -> str:
        """Extract the policy version from the engine."""
        # Direct attribute (stub engine)
        if hasattr(self.policy_engine, "version"):
            return str(self.policy_engine.version)
        # Real engine: policy is on _current_policy
        try:
            policy = self.policy_engine._current_policy
            return str(policy.version)
        except Exception:
            return "unknown"

    # ------------------------------------------------------------------
    # OpenAI format helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_openai_tool_calls(data: dict[str, Any]) -> list[ToolCall]:
        """Parse tool calls from an OpenAI chat completion response."""
        tool_calls: list[ToolCall] = []
        choices = data.get("choices", [])
        for choice in choices:
            message = choice.get("message", {})
            raw_calls = message.get("tool_calls", [])
            for tc in raw_calls:
                func = tc.get("function", {})
                try:
                    arguments = json.loads(func.get("arguments", "{}"))
                except (json.JSONDecodeError, TypeError):
                    arguments = {"_raw": func.get("arguments", "")}

                tool_calls.append(
                    ToolCall(
                        id=tc.get("id", ""),
                        name=func.get("name", "unknown"),
                        arguments=arguments,
                        raw=tc,
                        format=ToolCallFormat.OPENAI,
                    )
                )
        return tool_calls

    @staticmethod
    def _remove_openai_tool_call(data: dict[str, Any], tool_call_id: str) -> None:
        """Remove a specific tool call from an OpenAI response in place."""
        for choice in data.get("choices", []):
            message = choice.get("message", {})
            calls = message.get("tool_calls", [])
            message["tool_calls"] = [tc for tc in calls if tc.get("id") != tool_call_id]
            if not message["tool_calls"]:
                del message["tool_calls"]
                # Revert finish_reason from tool_calls to stop
                if choice.get("finish_reason") == "tool_calls":
                    choice["finish_reason"] = "stop"

    @staticmethod
    def _add_openai_denial_content(
        data: dict[str, Any], tool_name: str, reason: str
    ) -> None:
        """Add a content block explaining the denied tool call (OpenAI)."""
        denial_text = (
            f"[GhostGuard] Tool call '{tool_name}' was blocked: {reason}"
        )
        for choice in data.get("choices", []):
            message = choice.get("message", {})
            existing = message.get("content") or ""
            separator = "\n\n" if existing else ""
            message["content"] = existing + separator + denial_text

    # ------------------------------------------------------------------
    # Anthropic format helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_anthropic_tool_calls(data: dict[str, Any]) -> list[ToolCall]:
        """Parse tool calls from an Anthropic messages response."""
        tool_calls: list[ToolCall] = []
        content_blocks = data.get("content", [])
        for block in content_blocks:
            if block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.get("id", ""),
                        name=block.get("name", "unknown"),
                        arguments=block.get("input", {}),
                        raw=block,
                        format=ToolCallFormat.ANTHROPIC,
                    )
                )
        return tool_calls

    @staticmethod
    def _remove_anthropic_tool_call(data: dict[str, Any], tool_call_id: str) -> None:
        """Remove a tool_use block from an Anthropic response in place."""
        data["content"] = [
            block
            for block in data.get("content", [])
            if not (block.get("type") == "tool_use" and block.get("id") == tool_call_id)
        ]
        # Update stop_reason if no tool_use blocks remain
        has_tool_use = any(
            b.get("type") == "tool_use" for b in data.get("content", [])
        )
        if not has_tool_use and data.get("stop_reason") == "tool_use":
            data["stop_reason"] = "end_turn"

    @staticmethod
    def _add_anthropic_denial_content(
        data: dict[str, Any], tool_name: str, reason: str
    ) -> None:
        """Add a text block explaining the denied tool call (Anthropic)."""
        denial_text = (
            f"[GhostGuard] Tool call '{tool_name}' was blocked: {reason}"
        )
        data.setdefault("content", []).append(
            {"type": "text", "text": denial_text}
        )

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_format(data: dict[str, Any]) -> ToolCallFormat:
        """Detect whether a response is OpenAI or Anthropic format."""
        if "choices" in data:
            return ToolCallFormat.OPENAI
        if "content" in data and isinstance(data.get("content"), list):
            # Anthropic messages have content as a list of blocks
            if data.get("type") == "message" or data.get("role") == "assistant":
                return ToolCallFormat.ANTHROPIC
        return ToolCallFormat.UNKNOWN

    # ------------------------------------------------------------------
    # Main intercept method
    # ------------------------------------------------------------------

    async def intercept(
        self,
        response_data: dict[str, Any],
        session_id: str,
        request_id: str,
        upstream_model: str = "",
    ) -> dict[str, Any]:
        """Intercept and evaluate all tool calls in a response.

        Parameters
        ----------
        response_data:
            Parsed JSON body from the upstream LLM.
        session_id:
            GhostGuard session identifier.
        request_id:
            Unique request identifier.
        upstream_model:
            Model identifier from the upstream response.

        Returns
        -------
        dict
            The (possibly modified) response with denied tool calls removed
            and explanatory content added.
        """
        fmt = self.detect_format(response_data)

        if fmt == ToolCallFormat.OPENAI:
            tool_calls = self._extract_openai_tool_calls(response_data)
        elif fmt == ToolCallFormat.ANTHROPIC:
            tool_calls = self._extract_anthropic_tool_calls(response_data)
        else:
            logger.debug("Unknown response format, passing through")
            return response_data

        if not tool_calls:
            return response_data

        logger.info(
            "Intercepted %d tool call(s) in %s format [session=%s request=%s]",
            len(tool_calls),
            fmt.value,
            session_id,
            request_id,
        )

        if not upstream_model:
            upstream_model = response_data.get("model", "")

        for tc in tool_calls:
            start = time.monotonic()
            decision: Decision = await self._evaluate(tc)
            elapsed_ms = (time.monotonic() - start) * 1000

            # Build audit event
            event = AuditEvent(
                session_id=session_id,
                request_id=request_id,
                tool_name=tc.name,
                arguments=tc.arguments,
                verdict=decision.verdict.value,
                reason=decision.reason,
                tier=decision.tier,
                latency_ms=round(elapsed_ms, 2),
                upstream_model=upstream_model,
                policy_version=self._get_policy_version(),
            )
            await self.audit_store.log(event)

            if decision.verdict == Verdict.DENY:
                logger.warning(
                    "DENIED tool call '%s' [%s]: %s",
                    tc.name,
                    tc.id,
                    decision.reason,
                )
                if fmt == ToolCallFormat.OPENAI:
                    self._remove_openai_tool_call(response_data, tc.id)
                    self._add_openai_denial_content(
                        response_data, tc.name, decision.reason
                    )
                else:
                    self._remove_anthropic_tool_call(response_data, tc.id)
                    self._add_anthropic_denial_content(
                        response_data, tc.name, decision.reason
                    )
            elif decision.verdict == Verdict.SANDBOX:
                logger.info(
                    "SANDBOXED tool call '%s' [%s]",
                    tc.name,
                    tc.id,
                )
                # Mark the tool call for sandboxed execution
                if fmt == ToolCallFormat.OPENAI:
                    for choice in response_data.get("choices", []):
                        for raw_tc in choice.get("message", {}).get("tool_calls", []):
                            if raw_tc.get("id") == tc.id:
                                raw_tc["_ghostguard_sandbox"] = True
                else:
                    for block in response_data.get("content", []):
                        if block.get("id") == tc.id:
                            block["_ghostguard_sandbox"] = True
            else:
                logger.debug("ALLOWED tool call '%s' [%s]", tc.name, tc.id)

        return response_data

    # ------------------------------------------------------------------
    # Streaming support
    # ------------------------------------------------------------------

    def buffer_stream_chunk(
        self, request_id: str, chunk_data: dict[str, Any]
    ) -> None:
        """Buffer a single parsed SSE chunk for later evaluation.

        During streaming, tool call data arrives incrementally.  This
        method accumulates the chunks so that ``flush_decisions`` can
        evaluate complete tool calls once the stream ends.
        """
        self._stream_buffer.setdefault(request_id, []).append(chunk_data)

    async def flush_decisions(
        self,
        request_id: str,
        session_id: str,
        upstream_model: str = "",
    ) -> list[Decision]:
        """Evaluate all buffered tool calls for a completed stream.

        Returns a list of ``Decision`` objects for every tool call found
        in the buffered chunks.
        """
        chunks = self._stream_buffer.pop(request_id, [])
        if not chunks:
            return []

        # Reconstruct tool calls from streamed deltas (OpenAI format)
        assembled_calls: dict[int, dict[str, Any]] = {}
        for chunk in chunks:
            for choice in chunk.get("choices", []):
                delta = choice.get("delta", {})
                for tc in delta.get("tool_calls", []):
                    idx = tc.get("index", 0)
                    if idx not in assembled_calls:
                        assembled_calls[idx] = {
                            "id": tc.get("id", ""),
                            "function": {"name": "", "arguments": ""},
                        }
                    entry = assembled_calls[idx]
                    if tc.get("id"):
                        entry["id"] = tc["id"]
                    func = tc.get("function", {})
                    if func.get("name"):
                        entry["function"]["name"] = func["name"]
                    if func.get("arguments"):
                        entry["function"]["arguments"] += func["arguments"]

        decisions: list[Decision] = []
        for _idx, raw_tc in sorted(assembled_calls.items()):
            func = raw_tc["function"]
            try:
                arguments = json.loads(func["arguments"])
            except (json.JSONDecodeError, TypeError):
                arguments = {"_raw": func["arguments"]}

            tc = ToolCall(
                id=raw_tc["id"],
                name=func["name"],
                arguments=arguments,
                raw=raw_tc,
                format=ToolCallFormat.OPENAI,
            )

            start = time.monotonic()
            decision = await self._evaluate(tc)
            elapsed_ms = (time.monotonic() - start) * 1000

            event = AuditEvent(
                session_id=session_id,
                request_id=request_id,
                tool_name=tc.name,
                arguments=tc.arguments,
                verdict=decision.verdict.value,
                reason=decision.reason,
                tier=decision.tier,
                latency_ms=round(elapsed_ms, 2),
                upstream_model=upstream_model,
                policy_version=self._get_policy_version(),
            )
            await self.audit_store.log(event)
            decisions.append(decision)

        self._stream_decisions[request_id] = decisions
        return decisions
