"""
Auth Module
Tests for missing authentication, broken auth checks, and JWT weaknesses
on GraphQL fields.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re

from gqlpwn.core.requester import RequestError, Requester
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, GraphQLField, RunContext, ScanConfig

logger = get_logger(__name__)

# Patterns that indicate data was returned (not an auth error)
_DATA_PATTERNS = [re.compile(r'"data"\s*:\s*\{[^}]{5,}', re.S)]
_AUTH_ERROR_KEYWORDS = [
    "unauthorized",
    "unauthenticated",
    "forbidden",
    "access denied",
    "not authenticated",
    "not authorized",
    "jwt",
    "token",
    "login required",
    "401",
    "403",
]

_INVALID_TOKENS = [
    "invalid",
    "Bearer invalid.token.here",
    "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
]


def _looks_authorized(body: str) -> bool:
    """Heuristic: does the response look like it returned data (not an auth error)?"""
    body_lower = body.lower()
    if any(kw in body_lower for kw in _AUTH_ERROR_KEYWORDS):
        return False
    return any(p.search(body) for p in _DATA_PATTERNS)


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode (not verify) the payload of a JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Add padding
        payload_b64 = parts[1] + "=="
        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)
    except Exception:
        return None


def _forge_none_alg_jwt(original_token: str) -> str | None:
    """
    Attempt to forge a JWT with alg=none — only for testing purposes.
    Produces a token that skips signature verification on misconfigured servers.
    """
    try:
        parts = original_token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        # Strip signature
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


class AuthModule(BaseModule):
    """Tests for missing and broken authentication on GraphQL operations."""

    metadata = ModuleMetadata(
        name="auth",
        description="Tests missing auth, broken access controls, and JWT alg=none vulnerability",
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://portswigger.net/web-security/graphql/security-considerations",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []

        findings += await self._check_unauthenticated_access(ctx)
        findings += await self._check_jwt_none_alg(ctx)
        findings += await self._check_invalid_token_accepted(ctx)

        return findings

    # ------------------------------------------------------------------ #
    # Checks
    # ------------------------------------------------------------------ #

    async def _check_unauthenticated_access(self, ctx: RunContext) -> list[Finding]:
        """Re-send all requests without the Authorization header."""
        auth_header = ctx.config.headers.get("Authorization") or ctx.config.headers.get("authorization")
        if not auth_header:
            return []  # No auth configured — nothing to strip

        # Build a stripped config
        stripped_headers = {
            k: v for k, v in ctx.config.headers.items()
            if k.lower() != "authorization"
        }
        stripped_config = ctx.config.model_copy(update={"headers": stripped_headers})

        if not ctx.schema:
            return []

        findings: list[Finding] = []
        targets = ctx.schema.all_operations()[:10]  # cap to avoid hammering

        async with Requester(stripped_config) as anon_req:
            tasks = [
                self._probe_anon(ctx.url, anon_req, field)
                for field in targets
            ]
            results = await asyncio.gather(*tasks)

        for field, body in zip(targets, results):
            if body and _looks_authorized(body):
                findings.append(
                    self.finding(
                        title=f"Unauthenticated Access — {field.name}",
                        severity="high",
                        description=(
                            f"The field '{field.name}' returns data without an Authorization "
                            f"header. A request stripped of credentials received a non-error "
                            f"response, suggesting the resolver lacks authentication enforcement."
                        ),
                        endpoint=ctx.url,
                        payload=f"{{ {field.name} }}",
                        evidence=f"Unauthenticated response: {truncate(body, 300)}",
                        remediation=(
                            "Add authentication middleware to all resolvers, or use a "
                            "schema-level directive (e.g., @auth). Never rely solely on "
                            "the client to include tokens — enforce server-side."
                        ),
                    )
                )

        return findings

    async def _check_jwt_none_alg(self, ctx: RunContext) -> list[Finding]:
        """Test whether the server accepts a JWT with alg=none (signature bypass)."""
        auth = ctx.config.headers.get("Authorization") or ctx.config.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return []

        token = auth.split(" ", 1)[1]
        payload = _decode_jwt_payload(token)
        if not payload:
            return []

        forged = _forge_none_alg_jwt(token)
        if not forged:
            return []

        forged_config = ctx.config.model_copy(
            update={"headers": {**ctx.config.headers, "Authorization": f"Bearer {forged}"}}
        )

        # Use a safe, read-only probe query
        probe_query = "{ __typename }"
        try:
            async with Requester(forged_config) as req:
                resp = await req.graphql(probe_query)
                body = resp.text
                if '"__typename"' in body and "error" not in body.lower():
                    return [
                        self.finding(
                            title="JWT Algorithm Confusion — alg=none Accepted",
                            severity="critical",
                            description=(
                                "The server accepts a JWT with the algorithm set to 'none', "
                                "meaning no signature is required. An attacker can forge "
                                "arbitrary JWT payloads (e.g., escalate role to 'admin') "
                                "without knowing the signing secret."
                            ),
                            endpoint=ctx.url,
                            payload=f"Bearer {forged[:80]}…",
                            evidence=f"Server responded normally to alg=none JWT: {truncate(body, 200)}",
                            remediation=(
                                "Explicitly reject JWTs with alg=none in your token validation "
                                "library. In jsonwebtoken (Node.js): pass algorithms: ['HS256'] "
                                "or the specific expected algorithm to jwt.verify()."
                            ),
                            references=[
                                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                                "https://portswigger.net/web-security/jwt",
                            ],
                        )
                    ]
        except (RequestError, Exception):
            pass

        return []

    async def _check_invalid_token_accepted(self, ctx: RunContext) -> list[Finding]:
        """Send a clearly invalid token and see if the server still responds with data."""
        for bad_token in _INVALID_TOKENS:
            header_val = bad_token if bad_token.startswith("Bearer ") else f"Bearer {bad_token}"
            bad_config = ctx.config.model_copy(
                update={"headers": {**ctx.config.headers, "Authorization": header_val}}
            )
            try:
                async with Requester(bad_config) as req:
                    resp = await req.graphql("{ __typename }")
                    body = resp.text
                    if '"__typename"' in body and "error" not in body.lower():
                        return [
                            self.finding(
                                title="Invalid Bearer Token Accepted",
                                severity="high",
                                description=(
                                    "The server accepted a clearly invalid Bearer token "
                                    "and returned a successful response. This suggests "
                                    "token validation is missing or superficial."
                                ),
                                endpoint=ctx.url,
                                payload=header_val[:60],
                                evidence=f"Response to invalid token: {truncate(body, 200)}",
                                remediation=(
                                    "Ensure every protected resolver validates the token "
                                    "cryptographically before returning data. Do not treat "
                                    "the presence of any Bearer token as proof of authentication."
                                ),
                            )
                        ]
            except (RequestError, Exception):
                pass

        return []

    async def _probe_anon(self, url: str, req: Requester, field: GraphQLField) -> str | None:
        query = f"{{ {field.name} }}"
        try:
            resp = await req.graphql(query, url=url)
            return resp.text
        except (RequestError, Exception):
            return None
