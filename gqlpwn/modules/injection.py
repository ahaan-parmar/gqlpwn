"""
Injection Module
Tests GraphQL string arguments for SQLi, NoSQLi, command injection,
and server-side template injection (SSTI).
"""

from __future__ import annotations

import asyncio
import json

from gqlpwn.core.requester import RequestError
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import load_payload_file, truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

_SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{self.__class__.__mro__[1].__subclasses__()}}",
]
_SSTI_EVIDENCE = ["49", "[<class", "config"]

_CMDI_SLEEP_PAYLOADS = [
    "; sleep 3 #",
    "| sleep 3",
    "$(sleep 3)",
    "`sleep 3`",
]


class InjectionModule(BaseModule):
    """Tests injectable string arguments for common server-side injection vulnerabilities."""

    metadata = ModuleMetadata(
        name="injection",
        description="SQLi, NoSQLi, command injection, and SSTI via GraphQL string arguments",
        references=[
            "https://owasp.org/www-project-top-ten/",
            "https://graphql.org/learn/queries/#arguments",
            "https://portswigger.net/web-security/graphql",
        ],
    )

    def __init__(self) -> None:
        self._sqli = load_payload_file("sqli.json")
        self._nosqli = load_payload_file("nosqli.json")
        self._cmdi = load_payload_file("cmdi.json")

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            logger.warning("injection_no_schema")
            return []

        targets = ctx.schema.injectable_fields()
        if not targets:
            logger.info("injection_no_injectable_fields")
            return []

        logger.info("injection_targets", count=len(targets))
        tasks = [self._test_field(ctx, field) for field in targets]
        nested = await asyncio.gather(*tasks)
        return [f for batch in nested for f in batch]

    async def _test_field(self, ctx: RunContext, field: GraphQLField) -> list[Finding]:
        findings: list[Finding] = []
        req = ctx.requester

        for arg in field.args:
            if arg.type_name not in {"String", "String!", "ID", "ID!"}:
                continue

            findings += await self._test_sqli(ctx, req, field, arg.name)
            findings += await self._test_nosqli(ctx, req, field, arg.name)
            findings += await self._test_cmdi(ctx, req, field, arg.name)
            findings += await self._test_ssti(ctx, req, field, arg.name)

        return findings

    # ------------------------------------------------------------------ #
    # SQLi
    # ------------------------------------------------------------------ #

    async def _test_sqli(
        self, ctx: RunContext, req: object, field: GraphQLField, arg: str
    ) -> list[Finding]:
        payloads: list[str] = self._sqli.get("payloads", [])
        signatures: list[str] = self._sqli.get("error_signatures", [])

        for payload in payloads:
            query = self._build_query(field.name, arg, payload)
            try:
                resp = await req.graphql(query)  # type: ignore[union-attr]
                body = resp.text
                matched = next(
                    (s for s in signatures if s.lower() in body.lower()), None
                )
                if matched:
                    return [
                        self.finding(
                            title=f"SQL Injection — {field.name}.{arg}",
                            severity="critical",
                            description=(
                                f"The argument '{arg}' on field '{field.name}' appears "
                                f"vulnerable to SQL injection. A database error signature "
                                f"was detected in the response, suggesting unsanitized "
                                f"input is being interpolated into a SQL query."
                            ),
                            endpoint=ctx.url,
                            payload=payload,
                            evidence=f"Signature: '{matched}'. Response: {truncate(body, 400)}",
                            remediation=(
                                "Use parameterized queries or prepared statements. Never "
                                "concatenate user input directly into SQL strings. Use an ORM "
                                "that handles escaping automatically."
                            ),
                        )
                    ]
            except (RequestError, AttributeError):
                pass

        return []

    # ------------------------------------------------------------------ #
    # NoSQLi
    # ------------------------------------------------------------------ #

    async def _test_nosqli(
        self, ctx: RunContext, req: object, field: GraphQLField, arg: str
    ) -> list[Finding]:
        payloads: list[str] = self._nosqli.get("payloads", [])
        signatures: list[str] = self._nosqli.get("error_signatures", [])

        for payload in payloads:
            query = self._build_query(field.name, arg, payload)
            try:
                resp = await req.graphql(query)  # type: ignore[union-attr]
                body = resp.text
                matched = next(
                    (s for s in signatures if s.lower() in body.lower()), None
                )
                if matched:
                    return [
                        self.finding(
                            title=f"NoSQL Injection — {field.name}.{arg}",
                            severity="high",
                            description=(
                                f"The argument '{arg}' on field '{field.name}' may be "
                                f"vulnerable to NoSQL injection. A MongoDB/document-store "
                                f"error signature was detected in the server response."
                            ),
                            endpoint=ctx.url,
                            payload=payload,
                            evidence=f"Signature: '{matched}'. Response: {truncate(body, 400)}",
                            remediation=(
                                "Validate and sanitize all inputs before passing them to the "
                                "database layer. Use typed schemas (e.g., Mongoose) with strict "
                                "validation. Never pass raw GraphQL argument objects to MongoDB."
                            ),
                        )
                    ]
            except (RequestError, AttributeError):
                pass

        return []

    # ------------------------------------------------------------------ #
    # Command Injection
    # ------------------------------------------------------------------ #

    async def _test_cmdi(
        self, ctx: RunContext, req: object, field: GraphQLField, arg: str
    ) -> list[Finding]:
        payloads: list[str] = self._cmdi.get("payloads", [])
        signatures: list[str] = self._cmdi.get("error_signatures", [])

        for payload in payloads:
            query = self._build_query(field.name, arg, payload)
            try:
                resp = await req.graphql(query)  # type: ignore[union-attr]
                body = resp.text
                matched = next(
                    (s for s in signatures if s.lower() in body.lower()), None
                )
                if matched:
                    return [
                        self.finding(
                            title=f"Command Injection — {field.name}.{arg}",
                            severity="critical",
                            description=(
                                f"The argument '{arg}' on field '{field.name}' appears to "
                                f"execute system commands. Command output signature '{matched}' "
                                f"was found in the response."
                            ),
                            endpoint=ctx.url,
                            payload=payload,
                            evidence=f"OS signature: '{matched}'. Response: {truncate(body, 400)}",
                            remediation=(
                                "Never pass user-controlled input to shell commands. Use "
                                "subprocess with argument lists (not shell=True). Prefer "
                                "library functions over system calls."
                            ),
                        )
                    ]
            except (RequestError, AttributeError):
                pass

        return []

    # ------------------------------------------------------------------ #
    # SSTI
    # ------------------------------------------------------------------ #

    async def _test_ssti(
        self, ctx: RunContext, req: object, field: GraphQLField, arg: str
    ) -> list[Finding]:
        for payload in _SSTI_PAYLOADS:
            query = self._build_query(field.name, arg, payload)
            try:
                resp = await req.graphql(query)  # type: ignore[union-attr]
                body = resp.text
                matched = next(
                    (e for e in _SSTI_EVIDENCE if e in body), None
                )
                if matched:
                    return [
                        self.finding(
                            title=f"Server-Side Template Injection — {field.name}.{arg}",
                            severity="critical",
                            description=(
                                f"The argument '{arg}' on field '{field.name}' is rendered "
                                f"inside a server-side template engine. Template injection can "
                                f"lead to remote code execution."
                            ),
                            endpoint=ctx.url,
                            payload=payload,
                            evidence=f"Template evaluation output '{matched}' found in: {truncate(body, 300)}",
                            remediation=(
                                "Never render user input inside a template. Pass data to "
                                "templates as context variables, not as part of the template string."
                            ),
                        )
                    ]
            except (RequestError, AttributeError):
                pass

        return []

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_query(field: str, arg: str, value: str) -> str:
        escaped = value.replace('"', '\\"')
        return f'{{ {field}({arg}: "{escaped}") }}'
