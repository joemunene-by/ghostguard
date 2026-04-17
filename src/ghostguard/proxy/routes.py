"""FastAPI route definitions for the GhostGuard proxy.

Provides OpenAI-compatible and Anthropic-compatible proxy endpoints,
plus health and readiness probes.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.responses import Response

from ghostguard.proxy.interceptor import ToolCallInterceptor
from ghostguard.proxy.upstream import UpstreamClient, UpstreamError

logger = logging.getLogger(__name__)

router = APIRouter()

# These are set during app startup via set_dependencies().
_upstream: UpstreamClient | None = None
_interceptor: ToolCallInterceptor | None = None
_start_time: float = 0.0
_policy_name: str = "unknown"


def set_dependencies(
    upstream: UpstreamClient,
    interceptor: ToolCallInterceptor,
    start_time: float,
    policy_name: str,
) -> None:
    """Inject runtime dependencies into the route module."""
    global _upstream, _interceptor, _start_time, _policy_name
    _upstream = upstream
    _interceptor = interceptor
    _start_time = start_time
    _policy_name = policy_name


def _get_session_id(request: Request) -> str:
    """Extract or generate a session identifier."""
    return request.headers.get("x-ghostguard-session") or uuid.uuid4().hex


def _get_request_id(request: Request) -> str:
    """Retrieve the request ID injected by middleware."""
    return getattr(request.state, "request_id", uuid.uuid4().hex)


def _request_headers(request: Request) -> dict[str, str]:
    """Convert Starlette headers to a plain dict."""
    return dict(request.headers)


def _is_streaming(body: dict[str, Any]) -> bool:
    """Check if the request asks for SSE streaming."""
    return body.get("stream", False) is True


# ------------------------------------------------------------------
# Health / Readiness
# ------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint."""
    uptime = time.time() - _start_time if _start_time else 0
    return {
        "status": "ok",
        "policy": _policy_name,
        "uptime": round(uptime, 1),
    }


@router.get("/ready")
async def ready() -> JSONResponse:
    """Readiness probe — checks upstream connectivity."""
    assert _upstream is not None
    reachable = await _upstream.health_check()
    if reachable:
        return JSONResponse({"status": "ready", "upstream": "ok"})
    return JSONResponse(
        {"status": "not_ready", "upstream": "unreachable"},
        status_code=503,
    )


# ------------------------------------------------------------------
# OpenAI-compatible endpoint
# ------------------------------------------------------------------


@router.post("/v1/chat/completions", response_model=None)
async def openai_proxy(request: Request) -> Response:
    """Proxy OpenAI chat completions, intercepting tool calls."""
    assert _upstream is not None
    assert _interceptor is not None

    body_bytes = await request.body()
    headers = _request_headers(request)
    session_id = _get_session_id(request)
    request_id = _get_request_id(request)

    try:
        body_json = json.loads(body_bytes)
    except json.JSONDecodeError:
        return JSONResponse(
            {"error": {"message": "Invalid JSON body", "type": "invalid_request"}},
            status_code=400,
        )

    streaming = _is_streaming(body_json)

    try:
        if streaming:
            return await _handle_openai_stream(
                headers, body_bytes, session_id, request_id, body_json
            )
        else:
            return await _handle_openai_non_stream(
                headers, body_bytes, session_id, request_id
            )
    except UpstreamError as exc:
        logger.error("Upstream error on OpenAI endpoint: %s", exc)
        return JSONResponse(
            {"error": {"message": str(exc), "type": "upstream_error"}},
            status_code=exc.status_code,
        )


async def _handle_openai_non_stream(
    headers: dict[str, str],
    body_bytes: bytes,
    session_id: str,
    request_id: str,
) -> JSONResponse:
    """Handle a non-streaming OpenAI request."""
    assert _upstream is not None
    assert _interceptor is not None

    response = await _upstream.forward("POST", "/v1/chat/completions", headers, body_bytes)
    try:
        data = response.json()
    except Exception:
        return JSONResponse(
            {"error": {"message": "Invalid upstream response", "type": "upstream_error"}},
            status_code=502,
        )

    model = data.get("model", "")
    modified = await _interceptor.intercept(data, session_id, request_id, model)
    return JSONResponse(modified, status_code=response.status_code)


async def _handle_openai_stream(
    headers: dict[str, str],
    body_bytes: bytes,
    session_id: str,
    request_id: str,
    body_json: dict[str, Any],
) -> StreamingResponse:
    """Handle a streaming OpenAI request.

    Buffers tool call chunks for evaluation, then appends a final SSE
    event with GhostGuard decisions.
    """
    assert _upstream is not None
    assert _interceptor is not None

    async def generate():  # noqa: ANN202
        model = body_json.get("model", "")

        async for chunk in _upstream.forward_stream(
            "POST", "/v1/chat/completions", headers, body_bytes
        ):
            # Forward the chunk as-is to preserve low latency
            yield chunk

            # Also buffer for tool call evaluation
            text = chunk.decode("utf-8", errors="replace")
            for line in text.strip().split("\n"):
                line = line.strip()
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        chunk_data = json.loads(line[6:])
                        _interceptor.buffer_stream_chunk(request_id, chunk_data)
                    except json.JSONDecodeError:
                        pass

        # After stream completes, evaluate buffered tool calls
        decisions = await _interceptor.flush_decisions(
            request_id, session_id, model
        )

        # If any were denied, send a final SSE event
        denied = [d for d in decisions if d.verdict.value == "deny"]
        if denied:
            denial_msg = "\n".join(
                f"[GhostGuard] Tool "
                f"'{d.tool_call.name if d.tool_call else '?'}' "
                f"blocked: {d.reason}"
                for d in denied
            )
            event = {
                "choices": [
                    {
                        "delta": {"content": "\n\n" + denial_msg},
                        "index": 0,
                        "finish_reason": None,
                    }
                ],
                "ghostguard": True,
            }
            yield f"data: {json.dumps(event)}\n\n".encode()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-GhostGuard-Session": session_id,
        },
    )


# ------------------------------------------------------------------
# Anthropic-compatible endpoint
# ------------------------------------------------------------------


@router.post("/v1/messages", response_model=None)
async def anthropic_proxy(request: Request) -> Response:
    """Proxy Anthropic messages, intercepting tool_use blocks."""
    assert _upstream is not None
    assert _interceptor is not None

    body_bytes = await request.body()
    headers = _request_headers(request)
    session_id = _get_session_id(request)
    request_id = _get_request_id(request)

    try:
        body_json = json.loads(body_bytes)
    except json.JSONDecodeError:
        return JSONResponse(
            {"error": {"message": "Invalid JSON body", "type": "invalid_request"}},
            status_code=400,
        )

    streaming = body_json.get("stream", False)

    try:
        if streaming:
            return await _handle_anthropic_stream(
                headers, body_bytes, session_id, request_id
            )
        else:
            return await _handle_anthropic_non_stream(
                headers, body_bytes, session_id, request_id
            )
    except UpstreamError as exc:
        logger.error("Upstream error on Anthropic endpoint: %s", exc)
        return JSONResponse(
            {"error": {"message": str(exc), "type": "upstream_error"}},
            status_code=exc.status_code,
        )


async def _handle_anthropic_non_stream(
    headers: dict[str, str],
    body_bytes: bytes,
    session_id: str,
    request_id: str,
) -> JSONResponse:
    """Handle a non-streaming Anthropic request."""
    assert _upstream is not None
    assert _interceptor is not None

    response = await _upstream.forward("POST", "/v1/messages", headers, body_bytes)
    try:
        data = response.json()
    except Exception:
        return JSONResponse(
            {"error": {"message": "Invalid upstream response", "type": "upstream_error"}},
            status_code=502,
        )

    model = data.get("model", "")
    modified = await _interceptor.intercept(data, session_id, request_id, model)
    return JSONResponse(modified, status_code=response.status_code)


async def _handle_anthropic_stream(
    headers: dict[str, str],
    body_bytes: bytes,
    session_id: str,
    request_id: str,
) -> StreamingResponse:
    """Handle a streaming Anthropic request (pass-through for now)."""
    assert _upstream is not None

    async def generate():  # noqa: ANN202
        async for chunk in _upstream.forward_stream(
            "POST", "/v1/messages", headers, body_bytes
        ):
            yield chunk

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-GhostGuard-Session": session_id,
        },
    )
