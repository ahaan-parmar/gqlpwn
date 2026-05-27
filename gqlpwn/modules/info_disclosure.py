"""
Info Disclosure Module
Checks: introspection enabled, stack traces, debug extensions, Apollo tracing,
version fingerprinting, and field suggestions.
"""

from __future__ import annotations

import json
import re

from gqlpwn.core.requester import RequestError
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, RunContext

logger = get_logger(__name__)

_ERROR_PROBES = [
    '{ __typename { invalid } }',
    "{ nonExistentField_gqlpwn_probe }",
    '{ user(id: "\'") }',
    "query { }",
]

_VERSION_PATTERNS = [
    re.compile(r"apollo[- ]?server[/\s]?v?(\d+\.\d+[\.\d]*)", re.I),
    re.compile(r"graphql[- ]?v?(\d+\.\d+[\.\d]*)", re.I),
    re.compile(r"graphene[- ]?v?(\d+\.\d+[\.\d]*)", re.I),
    re.compile(r"strawberry[- ]?v?(\d+\.\d+[\.\d]*)", re.I),
    re.compile(r"hasura[- ]?v?(\d+\.\d+[\.\d]*)", re.I),
    re.compile(r"dgraph[- ]?v?(\d+\.\d+[\.\d]*)", re.I),
]

_STACK_SIGNATURES = [
    "Traceback (most recent call last)",
    "at Object.<anonymous>",
    "at Module._compile",
    "java.lang.",
    "org.springframework.",
    "System.Exception:",
    "NullReferenceException",
    "AttributeError:",
    "NameError:",
    "TypeError: Cannot",
    r'File "/',
    "stack trace:",
    "StackTrace:",
    "stacktrace",
    "at async ",
]


class InfoDisclosureModule(BaseModule):
    """Detects information leakage in GraphQL error responses and headers."""

    metadata = ModuleMetadata(
        name="info_disclosure",
        description="Detects introspection, debug mode, stack traces, and version leakage",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            "https://owasp.org/www-project-api-security/",
            "https://graphql.org/learn/introspection/",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []
        req = ctx.requester

        findings += self._check_introspection(ctx)
        findings += await self._check_debug_extensions(ctx, req)
        findings += await self._check_stack_traces(ctx, req)
        findings += await self._check_version_leakage(ctx, req)
        findings += await self._check_field_suggestions(ctx, req)

        return findings

    # ------------------------------------------------------------------ #
    # Checks
    # ------------------------------------------------------------------ #

    def _check_introspection(self, ctx: RunContext) -> list[Finding]:
        if not (ctx.schema and ctx.result.introspection_enabled):
            return []
        query_count = len(ctx.schema.queries)
        mutation_count = len(ctx.schema.mutations)
        return [
            self.finding(
                title="GraphQL Introspection Enabled",
                severity="medium",
                description=(
                    "Introspection is enabled, allowing any client to enumerate the complete "
                    "API schema including all types, queries, mutations, subscriptions, and "
                    "argument structures. This significantly reduces the effort needed to "
                    "map the attack surface and craft targeted attacks."
                ),
                endpoint=ctx.url,
                evidence=(
                    f"Full schema retrieved via __schema introspection. "
                    f"Found {query_count} queries, {mutation_count} mutations."
                ),
                remediation=(
                    "Disable introspection in production. In Apollo Server set "
                    "`introspection: false`. Consider persisted queries or an "
                    "operation allowlist as a defense-in-depth measure."
                ),
                references=[
                    "https://www.apollographql.com/docs/apollo-server/security/introspection/",
                    "https://escape.tech/blog/graphql-introspection-enabled/",
                ],
            )
        ]

    async def _check_debug_extensions(self, ctx: RunContext, req: object) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await req.graphql(_ERROR_PROBES[0])  # type: ignore[union-attr]
            body = req.parse_json(resp)  # type: ignore[union-attr]
            if not body or "extensions" not in body:
                return []

            ext: dict = body["extensions"]

            if "tracing" in ext:
                findings.append(
                    self.finding(
                        title="Apollo Query Tracing Enabled",
                        severity="low",
                        description=(
                            "Apollo Server query tracing is active. Tracing data exposes "
                            "resolver names, execution timing per field, and server-side "
                            "performance characteristics — all useful for an attacker "
                            "mapping resolver depth and identifying slow paths."
                        ),
                        endpoint=ctx.url,
                        evidence=f"extensions.tracing present: {truncate(json.dumps(ext.get('tracing', {})), 300)}",
                        remediation=(
                            "Disable Apollo tracing in production. Set `tracing: false` "
                            "in Apollo Server configuration or use `ApolloServerPluginUsageReporting`."
                        ),
                    )
                )

            for key in ("exception", "stacktrace", "errors"):
                if key in ext:
                    findings.append(
                        self.finding(
                            title="GraphQL Exception Details in extensions",
                            severity="high",
                            description=(
                                f"The server returns internal exception details under "
                                f"extensions.{key}. This can expose file paths, line numbers, "
                                f"internal class names, and framework internals to any client."
                            ),
                            endpoint=ctx.url,
                            evidence=f"extensions.{key}: {truncate(json.dumps(ext[key]), 400)}",
                            remediation=(
                                "Set NODE_ENV=production in Node.js apps or enable "
                                "`maskedErrors: true` in Apollo Server. Strip internal "
                                "error details in a custom formatError handler."
                            ),
                        )
                    )
        except (RequestError, AttributeError, KeyError, json.JSONDecodeError):
            pass

        return findings

    async def _check_stack_traces(self, ctx: RunContext, req: object) -> list[Finding]:
        seen_titles: set[str] = set()
        findings: list[Finding] = []

        for probe in _ERROR_PROBES:
            try:
                resp = await req.graphql(probe)  # type: ignore[union-attr]
                body_text = resp.text
                for sig in _STACK_SIGNATURES:
                    if sig.lower() in body_text.lower():
                        title = "Stack Trace Leaked in Error Response"
                        if title in seen_titles:
                            break
                        seen_titles.add(title)
                        findings.append(
                            self.finding(
                                title=title,
                                severity="high",
                                description=(
                                    "The server leaks internal stack trace information inside "
                                    "GraphQL error responses. Stack traces reveal file system "
                                    "paths, function names, line numbers, and dependency versions "
                                    "that substantially aid in crafting targeted exploits."
                                ),
                                endpoint=ctx.url,
                                payload=probe,
                                evidence=f"Signature '{sig}' found. Response: {truncate(body_text, 400)}",
                                remediation=(
                                    "Run the server in production mode (NODE_ENV=production for "
                                    "Node.js). Implement a custom error formatter that strips "
                                    "internal details and logs them server-side only."
                                ),
                            )
                        )
                        break
            except (RequestError, AttributeError):
                pass

        return findings

    async def _check_version_leakage(self, ctx: RunContext, req: object) -> list[Finding]:
        try:
            resp = await req.graphql(_ERROR_PROBES[1])  # type: ignore[union-attr]
            headers_str = str(dict(resp.headers))
            combined = headers_str + resp.text
            for pattern in _VERSION_PATTERNS:
                m = pattern.search(combined)
                if m:
                    return [
                        self.finding(
                            title="GraphQL Server Version Disclosed",
                            severity="info",
                            description=(
                                f"The server fingerprint reveals the GraphQL implementation "
                                f"version: {m.group(0)}. Version disclosure lets attackers "
                                f"look up CVEs and known weaknesses for that exact release."
                            ),
                            endpoint=ctx.url,
                            evidence=f"Version string: {m.group(0)}",
                            remediation=(
                                "Remove or genericize server-identifying headers (Server, X-Powered-By). "
                                "Ensure error messages do not embed version strings."
                            ),
                        )
                    ]
        except (RequestError, AttributeError):
            pass
        return []

    async def _check_field_suggestions(self, ctx: RunContext, req: object) -> list[Finding]:
        try:
            resp = await req.graphql("{ gqlpwn_nonexistent_xyzzy }")  # type: ignore[union-attr]
            body = resp.text
            if "did you mean" in body.lower():
                return [
                    self.finding(
                        title="Field Name Suggestions Enabled",
                        severity="low",
                        description=(
                            "The server returns field-name suggestions for invalid queries "
                            '(e.g., "Did you mean X?"). This allows schema enumeration even '
                            "when introspection is disabled, by iterating guesses and "
                            "harvesting suggestions from error messages."
                        ),
                        endpoint=ctx.url,
                        payload="{ gqlpwn_nonexistent_xyzzy }",
                        evidence=truncate(body, 300),
                        remediation=(
                            "Disable field suggestions. In graphql-js, wrap the schema "
                            "with a custom validation rule. Apollo Server users can use "
                            "the `@escape.tech/graphql-armor` package."
                        ),
                        references=[
                            "https://graphql-armor.escape.tech/docs/plugins/block-field-suggestions",
                        ],
                    )
                ]
        except (RequestError, AttributeError):
            pass
        return []
