"""
Deep GraphQL Enumeration Engine

Systematically fires every query/mutation in the schema with intelligently
constructed arguments, categorizes responses, and flags sensitive data exposure.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

from gqlpwn.core.requester import RequestError, Requester
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import GraphQLArgument, GraphQLField, ScanConfig

logger = get_logger(__name__)

# Keywords that flag a response as containing sensitive data
_SENSITIVE_PATTERNS = [
    re.compile(r'"email"\s*:\s*"[^@"]+@[^"]+\.[^"]{2,}"', re.I),
    re.compile(r'"password"', re.I),
    re.compile(r'"token"\s*:\s*"[^"]{20,}"', re.I),
    re.compile(r'"accessKey|secretKey|apiKey|api_key|secret"', re.I),
    re.compile(r'"phone|contact_number|mobile"', re.I),
    re.compile(r'"ssn|pan|aadhar|passport"', re.I),
    re.compile(r'"credit_card|card_number"', re.I),
    re.compile(r'"salary|billing|invoice|amount"', re.I),
]

_AUTH_ERROR_HINTS = [
    "unauthorized", "unauthenticated", "not authenticated",
    "access denied", "forbidden", "not authorized", "401", "403",
]

_GQL_ERROR_HINTS = [
    "cannot query field", "unknown argument", "field does not exist",
    "variable", "expected type", "got:", "required argument",
]


@dataclass
class QueryResult:
    field_name: str
    operation: str          # query | mutation
    query_sent: str
    status_code: int
    response_body: str
    has_data: bool
    is_auth_error: bool
    is_gql_error: bool
    sensitive_matches: list[str] = field(default_factory=list)
    error_message: str = ""

    @property
    def interesting(self) -> bool:
        return self.has_data or bool(self.sensitive_matches)


@dataclass
class EnumReport:
    target: str
    total_queries: int
    total_mutations: int
    accessible_queries: list[QueryResult] = field(default_factory=list)
    accessible_mutations: list[QueryResult] = field(default_factory=list)
    sensitive_findings: list[QueryResult] = field(default_factory=list)
    auth_blocked: list[str] = field(default_factory=list)
    gql_errors: list[str] = field(default_factory=list)


class Enumerator:
    """
    Fires every operation in the schema and categorizes responses.
    Builds a map of: what's accessible, what leaks data, what's locked.
    """

    def __init__(
        self,
        requester: Requester,
        org_id: str | None = None,
        concurrency: int = 5,
    ) -> None:
        self.requester = requester
        self.org_id = org_id
        self._sem = asyncio.Semaphore(concurrency)

    async def run_all(
        self,
        queries: list[GraphQLField],
        mutations: list[GraphQLField],
        target: str,
    ) -> EnumReport:
        report = EnumReport(
            target=target,
            total_queries=len(queries),
            total_mutations=len(mutations),
        )

        logger.info("enum_start", queries=len(queries), mutations=len(mutations))

        q_tasks = [self._probe(f, "query") for f in queries]
        m_tasks = [self._probe(f, "mutation") for f in mutations]

        q_results = await asyncio.gather(*q_tasks)
        m_results = await asyncio.gather(*m_tasks)

        for r in q_results:
            self._categorize(r, report, is_mutation=False)
        for r in m_results:
            self._categorize(r, report, is_mutation=True)

        logger.info(
            "enum_done",
            accessible_queries=len(report.accessible_queries),
            accessible_mutations=len(report.accessible_mutations),
            sensitive=len(report.sensitive_findings),
        )
        return report

    def _categorize(self, r: QueryResult, report: EnumReport, is_mutation: bool) -> None:
        if r.is_auth_error:
            report.auth_blocked.append(r.field_name)
        elif r.is_gql_error:
            report.gql_errors.append(r.field_name)
        elif r.has_data:
            if is_mutation:
                report.accessible_mutations.append(r)
            else:
                report.accessible_queries.append(r)

        if r.sensitive_matches:
            report.sensitive_findings.append(r)

    async def _probe(self, field: GraphQLField, operation: str) -> QueryResult:
        async with self._sem:
            query_str = self._build_query(field, operation)
            try:
                resp = await self.requester.graphql(query_str)
                body = resp.text
                return QueryResult(
                    field_name=field.name,
                    operation=operation,
                    query_sent=query_str,
                    status_code=resp.status_code,
                    response_body=body,
                    has_data=self._has_real_data(body, field.name),
                    is_auth_error=self._is_auth_error(body),
                    is_gql_error=self._is_gql_error(body),
                    sensitive_matches=self._find_sensitive(body),
                )
            except (RequestError, Exception) as exc:
                return QueryResult(
                    field_name=field.name,
                    operation=operation,
                    query_sent=query_str,
                    status_code=0,
                    response_body="",
                    has_data=False,
                    is_auth_error=False,
                    is_gql_error=False,
                    error_message=str(exc),
                )

    def _build_query(self, field: GraphQLField, operation: str) -> str:
        """Build the most minimal valid query for a field."""
        args = self._build_args(field.args)
        op = "mutation" if operation == "mutation" else "query"
        if args:
            return f"{op} {{ {field.name}({args}) }}"
        return f"{op} {{ {field.name} }}"

    def _build_args(self, args: list[GraphQLArgument]) -> str:
        """Fill required args with sensible test values."""
        parts: list[str] = []
        for arg in args:
            if not arg.is_required:
                continue
            val = self._default_value(arg)
            if val is not None:
                parts.append(f"{arg.name}: {val}")
        return ", ".join(parts)

    def _default_value(self, arg: GraphQLArgument) -> str | None:
        name_lower = arg.name.lower()
        t = arg.type_name.rstrip("!")

        # Org ID — use real one if we have it
        if "organization_id" in name_lower or "org_id" in name_lower:
            return f'"{self.org_id}"' if self.org_id else '"test-org-id"'

        # Limit / pagination
        if name_lower in ("limit", "size", "count", "page_size"):
            return "10"
        if name_lower in ("offset", "skip", "page"):
            return "0"
        if name_lower == "nexttoken":
            return "null"

        # Boolean flags
        if t == "Boolean":
            return "true"

        # Int
        if t in ("Int", "Float"):
            return "1"

        # Enum — skip (optional handling)
        if t.startswith("enum") or t[0].isupper():
            return None

        # Generic string
        if t in ("String", "ID", "AWSJSON", "AWSEmail"):
            return '"test"'

        return None

    @staticmethod
    def _has_real_data(body: str, field_name: str) -> bool:
        try:
            parsed = json.loads(body)
            data = parsed.get("data")
            if not data or not isinstance(data, dict):
                return False
            val = data.get(field_name)
            # null is not data; empty list is marginal; actual object/list is data
            if val is None:
                return False
            if isinstance(val, list) and len(val) == 0:
                return False
            return True
        except (json.JSONDecodeError, AttributeError):
            return False

    @staticmethod
    def _is_auth_error(body: str) -> bool:
        body_lower = body.lower()
        return any(h in body_lower for h in _AUTH_ERROR_HINTS)

    @staticmethod
    def _is_gql_error(body: str) -> bool:
        body_lower = body.lower()
        return any(h in body_lower for h in _GQL_ERROR_HINTS)

    @staticmethod
    def _find_sensitive(body: str) -> list[str]:
        return [p.pattern for p in _SENSITIVE_PATTERNS if p.search(body)]
