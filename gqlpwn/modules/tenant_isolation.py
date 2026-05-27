"""
Tenant Isolation Module
Tests whether organization_id-scoped queries enforce proper tenant boundaries.
A failure here means any authenticated user can read another org's data —
a critical multi-tenant BOLA vulnerability.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid

from gqlpwn.core.requester import RequestError
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

# Probe org IDs to try — mix of sequential, UUIDs, and common test values
_PROBE_ORG_IDS = [
    "1", "2", "3", "100", "admin",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    "ORG001", "ORG002", "org-1", "org-2",
    "test", "default", "root",
]

# Fields that are high-value targets for cross-tenant testing
_SENSITIVE_FIELD_HINTS = {
    "user", "audit", "billing", "payment", "invoice",
    "transaction", "log", "report", "ai", "api", "key",
    "secret", "setting", "config", "role", "permission",
}


def _body_hash(text: str) -> str:
    return hashlib.md5(" ".join(text.split()).encode()).hexdigest()


def _has_real_data(body: str, field_name: str) -> bool:
    try:
        parsed = json.loads(body)
        data = parsed.get("data", {}) or {}
        val = data.get(field_name)
        if val is None:
            return False
        if isinstance(val, (list, dict)) and not val:
            return False
        return True
    except (json.JSONDecodeError, AttributeError):
        return False


def _is_sensitive_field(name: str) -> bool:
    name_lower = name.lower()
    return any(hint in name_lower for hint in _SENSITIVE_FIELD_HINTS)


class TenantIsolationModule(BaseModule):
    """
    Tests multi-tenant isolation by probing organization_id-scoped queries
    with foreign org IDs.

    A hit means data from another tenant's organization is accessible
    with the current user's credentials — critical BOLA/IDOR.
    """

    metadata = ModuleMetadata(
        name="tenant_isolation",
        description="Tests cross-tenant data access via organization_id BOLA",
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://portswigger.net/web-security/access-control/idor",
            "https://salt.security/api-security-blog/what-is-bola",
        ],
    )

    def __init__(self, own_org_id: str | None = None) -> None:
        self.own_org_id = own_org_id

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        # Find all operations that take an organization_id argument
        org_scoped = self._find_org_scoped_fields(ctx.schema.all_operations())
        if not org_scoped:
            logger.info("tenant_isolation_no_org_scoped_fields")
            return []

        logger.info("tenant_isolation_targets", count=len(org_scoped))

        # First get a baseline with own org (confirm the query works at all)
        # Then try foreign org IDs
        tasks = [self._test_field(ctx, field) for field in org_scoped]
        nested = await asyncio.gather(*tasks)
        return [f for batch in nested for f in batch]

    def _find_org_scoped_fields(self, fields: list[GraphQLField]) -> list[GraphQLField]:
        result = []
        for f in fields:
            for arg in f.args:
                if "organization_id" in arg.name.lower() or "org_id" in arg.name.lower():
                    result.append(f)
                    break
        return result

    async def _test_field(self, ctx: RunContext, field: GraphQLField) -> list[Finding]:
        req = ctx.requester
        findings: list[Finding] = []

        # Get baseline with own org
        own_body = await self._query(req, field, self.own_org_id or "own-org")
        own_hash = _body_hash(own_body or "")
        own_has_data = _has_real_data(own_body or "", field.name)

        for probe_id in _PROBE_ORG_IDS:
            if probe_id == self.own_org_id:
                continue

            foreign_body = await self._query(req, field, probe_id)
            if not foreign_body:
                continue

            foreign_has_data = _has_real_data(foreign_body, field.name)
            foreign_hash = _body_hash(foreign_body)

            if foreign_has_data and foreign_hash != own_hash:
                severity = "critical" if _is_sensitive_field(field.name) else "high"
                findings.append(
                    self.finding(
                        title=f"Tenant Isolation Failure -- {field.name}",
                        severity=severity,
                        description=(
                            f"The field '{field.name}' returned data for organization_id='{probe_id}', "
                            f"which belongs to a different tenant. The currently authenticated user "
                            f"should only be able to access their own organization's data. "
                            f"This is a critical multi-tenant BOLA vulnerability allowing any "
                            f"authenticated user to access any other organization's data."
                        ),
                        endpoint=ctx.url,
                        payload=f'{field.name}(organization_id: "{probe_id}")',
                        evidence=truncate(foreign_body, 500),
                        remediation=(
                            "Enforce server-side tenant checks on every resolver. The organization_id "
                            "in the request must be validated against the authenticated user's "
                            "organization claim in the JWT — never trust client-supplied org IDs. "
                            "In AppSync, use $ctx.identity.claims to extract the verified org claim."
                        ),
                    )
                )
                # One confirmed finding per field is enough
                break

        return findings

    async def _query(self, req: object, field: GraphQLField, org_id: str) -> str | None:
        """Build and fire a query with the given org_id."""
        args_parts = [f'organization_id: "{org_id}"']

        # Add other required args with dummy values
        for arg in field.args:
            if "organization_id" in arg.name.lower():
                continue
            if arg.is_required:
                if arg.type_name.rstrip("!") in ("Int", "Float"):
                    args_parts.append(f"{arg.name}: 10")
                elif arg.type_name.rstrip("!") == "Boolean":
                    args_parts.append(f"{arg.name}: true")
                elif not arg.type_name[0].isupper():
                    args_parts.append(f'{arg.name}: "test"')

        args_str = ", ".join(args_parts)
        query = f"{{ {field.name}({args_str}) }}"

        try:
            resp = await req.graphql(query)  # type: ignore[union-attr]
            return resp.text
        except (RequestError, AttributeError):
            return None
