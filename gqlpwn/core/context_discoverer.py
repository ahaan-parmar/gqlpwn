"""
Context Discoverer
Automatically extracts user/org context from a JWT and live API probing.
No manual input needed — give it a token, it figures out who you are.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

from gqlpwn.core.requester import RequestError, Requester
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import GraphQLField, GraphQLSchema

logger = get_logger(__name__)

# Regex to find UUID-shaped strings in response bodies
_UUID_RE = re.compile(
    r'"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"',
    re.I,
)
# Org ID field name hints in response JSON
_ORG_KEY_RE = re.compile(
    r'"(organization_id|org_id|orgId|organisationId|tenantId|tenant_id)"\s*:\s*"([^"]+)"',
    re.I,
)
_USER_KEY_RE = re.compile(
    r'"(user_id|userId|sub|uid|memberId|member_id)"\s*:\s*"([^"]+)"',
    re.I,
)

# Queries we try first — commonly return caller context without args
_SELF_QUERY_NAMES = [
    "me", "getMe", "currentUser", "whoami", "self",
    "myProfile", "getProfile", "viewer", "getUser",
    "getUserDetails", "get_user_details", "user_details",
    "getMyOrganization", "myOrganization", "getOrganization",
]


@dataclass
class UserContext:
    """Everything discovered about the authenticated caller."""
    user_id: str | None = None
    email: str | None = None
    username: str | None = None
    org_id: str | None = None
    org_name: str | None = None
    role: str | None = None
    raw_claims: dict[str, Any] = field(default_factory=dict)
    raw_profile: dict[str, Any] = field(default_factory=dict)
    discovery_log: list[str] = field(default_factory=list)

    def log(self, msg: str) -> None:
        self.discovery_log.append(msg)
        logger.info("context_discovery", msg=msg)

    def summary(self) -> str:
        lines = [
            f"  user_id  : {self.user_id or 'unknown'}",
            f"  email    : {self.email or 'unknown'}",
            f"  username : {self.username or 'unknown'}",
            f"  org_id   : {self.org_id or 'NOT FOUND'}",
            f"  org_name : {self.org_name or 'unknown'}",
            f"  role     : {self.role or 'unknown'}",
        ]
        return "\n".join(lines)


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode JWT payload without verifying signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        padding = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(padding)
        return json.loads(decoded)
    except Exception:
        return {}


def _extract_from_response(body: str) -> dict[str, str]:
    """Pull org_id and user_id out of any JSON response body."""
    result: dict[str, str] = {}
    for m in _ORG_KEY_RE.finditer(body):
        result["org_id"] = m.group(2)
    for m in _USER_KEY_RE.finditer(body):
        result["user_id"] = m.group(2)
    return result


def _find_in_json(data: Any, target_keys: set[str], depth: int = 0) -> str | None:
    """Recursively search a parsed JSON object for a target key."""
    if depth > 8 or data is None:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in target_keys and isinstance(v, str) and v:
                return v
            result = _find_in_json(v, target_keys, depth + 1)
            if result:
                return result
    elif isinstance(data, list):
        for item in data:
            result = _find_in_json(item, target_keys, depth + 1)
            if result:
                return result
    return None


_ORG_KEYS = {"organization_id", "org_id", "orgid", "tenantid", "tenant_id", "organisationid"}
_ORG_NAME_KEYS = {"organization_name", "org_name", "orgname", "tenantname", "company_name", "companyname"}
_ROLE_KEYS = {"role", "user_type", "usertype", "user_role", "userrole", "account_type"}


class ContextDiscoverer:
    """
    Automatically discovers who the authenticated user is and what
    organization they belong to, using JWT decoding + live API probing.
    """

    def __init__(self, requester: Requester, token: str) -> None:
        self.requester = requester
        self.token = token
        self.claims = _decode_jwt_payload(token)

    async def discover(self, schema: GraphQLSchema) -> UserContext:
        ctx = UserContext()

        # Phase 1: extract what we can from the JWT itself
        self._extract_jwt_claims(ctx)

        # Phase 2: probe "self" style queries (me, currentUser, etc.)
        await self._probe_self_queries(ctx, schema)

        # Phase 3: probe zero-arg queries that might return org context
        if not ctx.org_id:
            await self._probe_zero_arg_queries(ctx, schema)

        # Phase 4: if we have user_id, try to call get_user by ID
        if not ctx.org_id and ctx.user_id:
            await self._probe_user_by_id(ctx, schema)

        # Phase 5: fuzzing org_id via list queries that return org info
        if not ctx.org_id:
            await self._probe_org_discovery_queries(ctx, schema)

        if ctx.org_id:
            ctx.log(f"org_id confirmed: {ctx.org_id}")
        else:
            ctx.log("org_id NOT discovered — tenant isolation tests may be limited")

        return ctx

    # ------------------------------------------------------------------ #
    # Phase 1 — JWT
    # ------------------------------------------------------------------ #

    def _extract_jwt_claims(self, ctx: UserContext) -> None:
        ctx.raw_claims = self.claims
        ctx.user_id = (
            self.claims.get("sub")
            or self.claims.get("user_id")
            or self.claims.get("uid")
        )
        ctx.email = self.claims.get("email")
        ctx.username = (
            self.claims.get("cognito:username")
            or self.claims.get("username")
            or self.claims.get("preferred_username")
        )
        ctx.org_id = (
            self.claims.get("organization_id")
            or self.claims.get("org_id")
            or self.claims.get("custom:org_id")
            or self.claims.get("custom:organization_id")
            or self.claims.get("tenantId")
        )
        ctx.role = (
            self.claims.get("custom:role")
            or self.claims.get("role")
            or self.claims.get("user_type")
        )
        if ctx.user_id:
            ctx.log(f"JWT user_id={ctx.user_id}")
        if ctx.email:
            ctx.log(f"JWT email={ctx.email}")
        if ctx.org_id:
            ctx.log(f"JWT org_id={ctx.org_id} (from token claim)")

    # ------------------------------------------------------------------ #
    # Phase 2 — self queries
    # ------------------------------------------------------------------ #

    async def _probe_self_queries(self, ctx: UserContext, schema: GraphQLSchema) -> None:
        self_fields = [
            f for f in schema.queries
            if f.name.lower() in {n.lower() for n in _SELF_QUERY_NAMES}
            or not any(a.is_required for a in f.args)
        ]
        for field in self_fields[:20]:
            body = await self._fire(f"{{ {field.name} }}")
            if not body:
                continue
            self._try_extract(ctx, body, source=field.name)
            if ctx.org_id:
                return

    # ------------------------------------------------------------------ #
    # Phase 3 — zero-arg queries
    # ------------------------------------------------------------------ #

    async def _probe_zero_arg_queries(self, ctx: UserContext, schema: GraphQLSchema) -> None:
        zero_arg = [f for f in schema.queries if not f.args]
        for field in zero_arg[:30]:
            body = await self._fire(f"{{ {field.name} }}")
            if not body:
                continue
            self._try_extract(ctx, body, source=field.name)
            if ctx.org_id:
                return

    # ------------------------------------------------------------------ #
    # Phase 4 — user by ID
    # ------------------------------------------------------------------ #

    async def _probe_user_by_id(self, ctx: UserContext, schema: GraphQLSchema) -> None:
        if not ctx.user_id:
            return
        id_arg_names = ("id", "user_id", "userId", "member_id", "memberId")
        for field in schema.queries:
            for arg in field.args:
                if arg.name.lower() in {n.lower() for n in id_arg_names} and not any(
                    a.is_required and a.name != arg.name for a in field.args
                ):
                    body = await self._fire(f'{{ {field.name}({arg.name}: "{ctx.user_id}") }}')
                    if body:
                        self._try_extract(ctx, body, source=f"{field.name}(id)")
                        if ctx.org_id:
                            return

    # ------------------------------------------------------------------ #
    # Phase 5 — org discovery queries
    # ------------------------------------------------------------------ #

    async def _probe_org_discovery_queries(self, ctx: UserContext, schema: GraphQLSchema) -> None:
        """Look for queries whose name suggests they return org info."""
        org_hints = ("organization", "org", "tenant", "company", "account", "workspace")
        for field in schema.queries:
            if not any(h in field.name.lower() for h in org_hints):
                continue
            # Build with just non-org required args
            args = self._build_minimal_args(field, ctx)
            query = f"{{ {field.name}({args}) }}" if args else f"{{ {field.name} }}"
            body = await self._fire(query)
            if body:
                self._try_extract(ctx, body, source=field.name)
                if ctx.org_id:
                    return

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _try_extract(self, ctx: UserContext, body: str, source: str) -> None:
        """Try to pull org_id, org_name, role from a response body."""
        try:
            parsed = json.loads(body)
            data = parsed.get("data", {})
            if not data:
                return

            if not ctx.org_id:
                found = _find_in_json(data, _ORG_KEYS)
                if found:
                    ctx.org_id = found
                    ctx.log(f"org_id='{found}' discovered via {source}")

            if not ctx.org_name:
                found = _find_in_json(data, _ORG_NAME_KEYS)
                if found:
                    ctx.org_name = found
                    ctx.log(f"org_name='{found}' via {source}")

            if not ctx.role:
                found = _find_in_json(data, _ROLE_KEYS)
                if found:
                    ctx.role = found
                    ctx.log(f"role='{found}' via {source}")

            if not ctx.user_id:
                found = _find_in_json(data, {"sub", "user_id", "userid", "uid", "member_id"})
                if found:
                    ctx.user_id = found

            # Merge into raw profile
            if isinstance(data, dict):
                ctx.raw_profile.update(data)

        except (json.JSONDecodeError, AttributeError):
            pass

    def _build_minimal_args(self, field: GraphQLField, ctx: UserContext) -> str:
        parts: list[str] = []
        for arg in field.args:
            if not arg.is_required:
                continue
            name_lower = arg.name.lower()
            t = arg.type_name.rstrip("!")

            if "organization_id" in name_lower or "org_id" in name_lower:
                val = f'"{ctx.org_id}"' if ctx.org_id else None
            elif "user_id" in name_lower or name_lower == "id":
                val = f'"{ctx.user_id}"' if ctx.user_id else None
            elif "email" in name_lower:
                val = f'"{ctx.email}"' if ctx.email else None
            elif t in ("Int", "Float"):
                val = "10"
            elif t == "Boolean":
                val = "true"
            elif t.startswith("enum") or (t and t[0].isupper()):
                val = None
            else:
                val = '"test"'

            if val:
                parts.append(f"{arg.name}: {val}")
        return ", ".join(parts)

    async def _fire(self, query: str) -> str | None:
        try:
            resp = await self.requester.graphql(query)
            if resp.status_code in (200, 400):
                return resp.text
        except (RequestError, Exception):
            pass
        return None
