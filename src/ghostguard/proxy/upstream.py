"""Async HTTP client for forwarding requests to upstream LLM APIs.

Handles both streaming (SSE) and non-streaming requests, passing through
authorization headers while stripping hop-by-hop headers.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import httpx

logger = logging.getLogger(__name__)

# Headers that should NOT be forwarded to the upstream.
_HOP_BY_HOP = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
    }
)


class UpstreamError(Exception):
    """Raised when the upstream LLM API returns an error."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"Upstream returned {status_code}: {body[:200]}")


class UpstreamClient:
    """Async HTTP client that forwards requests to the real LLM provider.

    Parameters
    ----------
    base_url:
        The root URL of the upstream API (e.g. ``https://api.openai.com``).
    timeout:
        Default request timeout in seconds.
    """

    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                ),
            )
        return self._client

    def _filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Remove hop-by-hop and host headers; keep Authorization etc."""
        return {
            k: v
            for k, v in headers.items()
            if k.lower() not in _HOP_BY_HOP
        }

    async def forward(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> httpx.Response:
        """Forward a non-streaming request and return the full response.

        Parameters
        ----------
        method:
            HTTP method (POST, GET, etc.).
        path:
            Request path (e.g. ``/v1/chat/completions``).
        headers:
            Request headers from the client.
        body:
            Raw request body bytes.

        Returns
        -------
        httpx.Response
            The full response from the upstream API.
        """
        client = await self._ensure_client()
        clean_headers = self._filter_headers(headers)

        try:
            response = await client.request(
                method=method,
                url=path,
                headers=clean_headers,
                content=body,
            )
            if response.status_code >= 500:
                logger.error(
                    "Upstream server error: %d %s",
                    response.status_code,
                    response.text[:200],
                )
            return response
        except httpx.TimeoutException as exc:
            logger.error("Upstream request timed out: %s", exc)
            raise UpstreamError(504, f"Upstream timeout: {exc}") from exc
        except httpx.ConnectError as exc:
            logger.error("Cannot connect to upstream: %s", exc)
            raise UpstreamError(502, f"Upstream unreachable: {exc}") from exc
        except httpx.HTTPError as exc:
            logger.error("Upstream HTTP error: %s", exc)
            raise UpstreamError(502, f"Upstream error: {exc}") from exc

    async def forward_stream(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> AsyncIterator[bytes]:
        """Forward a streaming request and yield SSE chunks.

        Yields raw bytes as they arrive from upstream, suitable for
        proxying an SSE stream back to the client.
        """
        client = await self._ensure_client()
        clean_headers = self._filter_headers(headers)

        try:
            async with client.stream(
                method=method,
                url=path,
                headers=clean_headers,
                content=body,
            ) as response:
                if response.status_code >= 400:
                    error_body = await response.aread()
                    raise UpstreamError(
                        response.status_code,
                        error_body.decode("utf-8", errors="replace"),
                    )

                async for chunk in response.aiter_bytes():
                    yield chunk
        except httpx.TimeoutException as exc:
            logger.error("Upstream stream timed out: %s", exc)
            raise UpstreamError(504, f"Upstream stream timeout: {exc}") from exc
        except httpx.ConnectError as exc:
            logger.error("Cannot connect to upstream for stream: %s", exc)
            raise UpstreamError(502, f"Upstream unreachable: {exc}") from exc

    async def health_check(self) -> bool:
        """Return True if the upstream is reachable."""
        client = await self._ensure_client()
        try:
            resp = await client.get("/", timeout=5.0)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
