"""Async HTTP client wrapper with retry logic, proxy support, and rate limiting."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import ScanConfig

logger = get_logger(__name__)

_BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "gqlpwn/1.0 (GraphQL Security Scanner)",
}


class RequestError(Exception):
    """Raised when a request fails after all retry attempts."""


class Requester:
    """
    Shared async HTTP session for all gqlpwn network I/O.

    Use as an async context manager:
        async with Requester(config) as req:
            resp = await req.graphql("{ __typename }")
    """

    def __init__(self, config: ScanConfig, max_retries: int = 3) -> None:
        self.config = config
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None
        self._concurrency = asyncio.Semaphore(config.concurrency)

    async def __aenter__(self) -> "Requester":
        merged_headers = {**_BASE_HEADERS, **self.config.headers}
        proxy_arg: dict[str, Any] = {}
        if self.config.proxy:
            proxy_arg["proxy"] = self.config.proxy

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            headers=merged_headers,
            cookies=self.config.cookies,
            follow_redirects=True,
            verify=False,  # intentional — target certs are often self-signed in pentest
            **proxy_arg,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        url: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Send a single GraphQL operation."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        return await self._post(url or self.config.url, payload, extra_headers=extra_headers)

    async def graphql_batch(
        self,
        operations: list[dict[str, Any]],
        url: str | None = None,
    ) -> httpx.Response:
        """Send a batched array of GraphQL operations in a single request."""
        return await self._post(url or self.config.url, operations)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """HTTP GET with retry."""
        return await self._request("GET", url, **kwargs)

    # ------------------------------------------------------------------ #
    # Internal
    # ------------------------------------------------------------------ #

    async def _post(
        self,
        url: str,
        body: Any,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        kwargs: dict[str, Any] = {"json": body}
        if extra_headers:
            kwargs["headers"] = extra_headers
        return await self._request("POST", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        async with self._concurrency:
            if self.config.rate_limit > 0:
                await asyncio.sleep(self.config.rate_limit)

            last_exc: Exception | None = None
            for attempt in range(1, self.max_retries + 1):
                try:
                    assert self._client is not None, "Requester must be used as async context manager"
                    resp = await self._client.request(method, url, **kwargs)
                    logger.debug(
                        "http_request",
                        method=method,
                        url=url,
                        status=resp.status_code,
                        attempt=attempt,
                    )
                    return resp
                except httpx.TimeoutException as exc:
                    last_exc = exc
                    logger.warning("request_timeout", url=url, attempt=attempt)
                except httpx.RequestError as exc:
                    last_exc = exc
                    logger.warning("request_error", url=url, error=str(exc), attempt=attempt)

                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)

            raise RequestError(
                f"{method} {url} failed after {self.max_retries} attempts"
            ) from last_exc

    def parse_json(self, response: httpx.Response) -> dict[str, Any] | None:
        """Safe JSON parse; returns None on failure."""
        try:
            return response.json()  # type: ignore[no-any-return]
        except (json.JSONDecodeError, ValueError):
            return None
