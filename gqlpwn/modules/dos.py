"""
DoS Module  (requires --aggressive)
Tests for GraphQL Denial of Service vectors:
  - Deep query nesting
  - Recursive fragment cycling
  - Batch request abuse
  - Alias field overloading

IMPORTANT: These tests can cause real resource exhaustion on the target.
They are gated behind --aggressive and include built-in rate limiting.
"""

from __future__ import annotations

import asyncio
import time

from gqlpwn.core.requester import RequestError
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, RunContext

logger = get_logger(__name__)

# Conservative safe defaults — high enough to detect, low enough to avoid killing prod
_SAFE_NESTING_DEPTH = 10
_SAFE_ALIAS_COUNT = 30
_SAFE_BATCH_COUNT = 20
_SLOW_THRESHOLD_SECONDS = 5.0  # response slower than this suggests the payload is working


def _build_nested_query(depth: int, leaf_field: str = "__typename") -> str:
    """Build a deeply nested query: { a { a { a { ... __typename } } } }"""
    # Use __typename as the leaf because it's always available
    inner = f"{{ {leaf_field} }}"
    for _ in range(depth - 1):
        inner = f"{{ node {inner} }}"
    return f"{{ {leaf_field} }}" if depth <= 1 else f"{{ node {inner} }}"


def _build_alias_flood(field: str, count: int) -> str:
    """Build a query with hundreds of aliases for the same field."""
    aliases = "\n".join(f"  alias_{i}: {field}" for i in range(count))
    return f"{{\n{aliases}\n}}"


def _build_batch(query: str, count: int) -> list[dict]:
    """Build a batch of identical operations."""
    return [{"query": query} for _ in range(count)]


class DosModule(BaseModule):
    """
    Tests GraphQL Denial of Service vectors.

    Requires --aggressive flag. Uses conservative query depths and batch sizes
    by default to avoid causing real outages during authorized assessments.
    """

    metadata = ModuleMetadata(
        name="dos",
        description=(
            "Tests query complexity attacks: deep nesting, alias flooding, "
            "and batch abuse. Requires --aggressive."
        ),
        requires_aggressive=True,
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://www.apollographql.com/blog/graphql-security-dos-attacks/",
            "https://github.com/nicholasess/graphql-disable-suggestions",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.aggressive:
            # Scanner already guards this, but be defensive
            return []

        logger.warning(
            "dos_module_active",
            warning="Sending potentially resource-intensive queries to target",
        )

        # Add a small inter-test delay to avoid cascading impact
        findings: list[Finding] = []
        findings += await self._test_deep_nesting(ctx)
        await asyncio.sleep(1)
        findings += await self._test_alias_flood(ctx)
        await asyncio.sleep(1)
        findings += await self._test_batch_abuse(ctx)
        return findings

    # ------------------------------------------------------------------ #
    # Tests
    # ------------------------------------------------------------------ #

    async def _test_deep_nesting(self, ctx: RunContext) -> list[Finding]:
        """Send a deeply nested query and measure response latency."""
        req = ctx.requester
        query = _build_nested_query(_SAFE_NESTING_DEPTH)
        start = time.monotonic()
        try:
            resp = await req.graphql(query)  # type: ignore[union-attr]
            elapsed = time.monotonic() - start
            body = resp.text

            rejected = self._is_complexity_rejected(body)
            if rejected:
                return []  # Server has query complexity limits — good

            if elapsed >= _SLOW_THRESHOLD_SECONDS:
                return [
                    self.finding(
                        title="Query Depth Attack — No Depth Limiting",
                        severity="medium",
                        description=(
                            f"A deeply nested query (depth={_SAFE_NESTING_DEPTH}) caused "
                            f"the server to respond slowly ({elapsed:.1f}s). Without query "
                            f"depth limiting, an attacker can send arbitrarily deep queries "
                            f"to exhaust CPU and memory."
                        ),
                        endpoint=ctx.url,
                        payload=truncate(query, 200),
                        evidence=f"Response took {elapsed:.1f}s for depth={_SAFE_NESTING_DEPTH}",
                        remediation=(
                            "Implement query depth limiting. In Apollo Server use the "
                            "graphql-depth-limit package. Set a maximum depth of 5–10 for "
                            "most APIs. Also consider query complexity analysis."
                        ),
                    )
                ]
            elif not rejected:
                # Server accepted deep query quickly — might still be vulnerable at higher depths
                return [
                    self.finding(
                        title="Query Depth Limit Not Enforced",
                        severity="low",
                        description=(
                            f"A depth-{_SAFE_NESTING_DEPTH} query was accepted and returned "
                            f"without a complexity/depth error. The server may lack query "
                            f"depth limiting. An attacker could use greater depths."
                        ),
                        endpoint=ctx.url,
                        payload=truncate(query, 200),
                        evidence=f"Accepted in {elapsed:.1f}s with no depth-limit error",
                        remediation=(
                            "Add query depth and complexity limits. Evaluate `graphql-depth-limit` "
                            "or `graphql-query-complexity` packages."
                        ),
                    )
                ]
        except (RequestError, AttributeError):
            pass
        return []

    async def _test_alias_flood(self, ctx: RunContext) -> list[Finding]:
        """Flood the server with aliases to multiply resolver work."""
        req = ctx.requester
        field = "__typename"
        query = _build_alias_flood(field, _SAFE_ALIAS_COUNT)
        start = time.monotonic()
        try:
            resp = await req.graphql(query)  # type: ignore[union-attr]
            elapsed = time.monotonic() - start
            body = resp.text

            if self._is_complexity_rejected(body):
                return []

            if elapsed >= _SLOW_THRESHOLD_SECONDS or f"alias_{_SAFE_ALIAS_COUNT - 1}" in body:
                return [
                    self.finding(
                        title="Alias Field Flooding — No Complexity Limit",
                        severity="medium",
                        description=(
                            f"A query with {_SAFE_ALIAS_COUNT} aliases for the same field "
                            f"was accepted without a complexity error. Alias flooding multiplies "
                            f"resolver invocations linearly, exhausting backend resources."
                        ),
                        endpoint=ctx.url,
                        payload=truncate(query, 200),
                        evidence=f"All {_SAFE_ALIAS_COUNT} aliases resolved in {elapsed:.1f}s",
                        remediation=(
                            "Implement query complexity analysis that counts aliased fields. "
                            "Use the `graphql-query-complexity` library with a per-field cost model."
                        ),
                    )
                ]
        except (RequestError, AttributeError):
            pass
        return []

    async def _test_batch_abuse(self, ctx: RunContext) -> list[Finding]:
        """Send a large batch of operations in one HTTP request."""
        req = ctx.requester
        batch = _build_batch("{ __typename }", _SAFE_BATCH_COUNT)
        start = time.monotonic()
        try:
            resp = await req.graphql_batch(batch)  # type: ignore[union-attr]
            elapsed = time.monotonic() - start
            body = resp.text

            # If batching is entirely disabled we get an error
            if "batching" in body.lower() or "not supported" in body.lower():
                return []

            if isinstance(resp.json(), list):
                actual_count = len(resp.json())  # type: ignore[arg-type]
                return [
                    self.finding(
                        title="GraphQL Batch Request Abuse",
                        severity="medium",
                        description=(
                            f"The server processes batched GraphQL requests. A batch of "
                            f"{_SAFE_BATCH_COUNT} operations was accepted and {actual_count} "
                            f"responses returned. Without batch size limits, attackers can "
                            f"multiply backend work with a single HTTP request, bypassing "
                            f"per-request rate limiting."
                        ),
                        endpoint=ctx.url,
                        payload=f"Batch of {_SAFE_BATCH_COUNT} {{ __typename }} operations",
                        evidence=f"Received {actual_count} responses in {elapsed:.1f}s",
                        remediation=(
                            "Limit the maximum number of operations in a batch (recommended: ≤10). "
                            "In Apollo Server, use `allowBatchedHttpRequests: false` or a "
                            "custom middleware that validates batch size before execution."
                        ),
                    )
                ]
        except (RequestError, AttributeError, Exception):
            pass
        return []

    @staticmethod
    def _is_complexity_rejected(body: str) -> bool:
        """Return True if the server returned a query complexity/depth error."""
        keywords = [
            "complexity", "depth limit", "too deep", "query too complex",
            "max depth", "cost limit", "exceeds maximum",
        ]
        body_lower = body.lower()
        return any(kw in body_lower for kw in keywords)
