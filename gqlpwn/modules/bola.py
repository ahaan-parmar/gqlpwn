"""
BOLA / IDOR Module
Detects Broken Object Level Authorization by probing ID-based fields
with sequential and out-of-range identifiers, then comparing responses
to detect unauthorized data access.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from gqlpwn.core.requester import RequestError
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

_PROBE_IDS = [
    "1", "2", "3", "0", "-1",
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
]

# Response body similarity threshold — below this we consider the responses meaningfully different
_SIMILARITY_THRESHOLD = 0.95


def _body_fingerprint(text: str) -> str:
    """Stable hash of a response body for quick comparison."""
    normalized = " ".join(text.split())  # collapse whitespace
    return hashlib.sha256(normalized.encode()).hexdigest()


def _bodies_differ(a: str, b: str) -> bool:
    """Return True if two response bodies carry meaningfully different content."""
    if not a or not b:
        return False
    # Quick length heuristic first
    ratio = min(len(a), len(b)) / max(len(a), len(b)) if max(len(a), len(b)) > 0 else 1.0
    if ratio < _SIMILARITY_THRESHOLD:
        return True
    return _body_fingerprint(a) != _body_fingerprint(b)


def _looks_like_data(body: str) -> bool:
    """Heuristic: does the response actually return object data?"""
    try:
        parsed = json.loads(body)
        data = parsed.get("data")
        if not data:
            return False
        # If any data field is non-null and not just {"__typename": ...}
        if isinstance(data, dict):
            for v in data.values():
                if v is not None and v != {} and v != []:
                    return True
    except (json.JSONDecodeError, AttributeError):
        pass
    return False


class BolaModule(BaseModule):
    """
    Probes ID-accepting fields for Broken Object Level Authorization (IDOR/BOLA).

    Strategy:
    1. Identify fields with ID or Int arguments
    2. Send a baseline request with the authenticated user's implied ID
    3. Probe other sequential IDs
    4. Flag any probe that returns non-null data with a different fingerprint
       than a provably invalid ID response
    """

    metadata = ModuleMetadata(
        name="bola",
        description="Detects IDOR/BOLA in ID-based GraphQL fields via response comparison",
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://salt.security/api-security-blog/what-is-bola",
            "https://portswigger.net/web-security/access-control/idor",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        targets = ctx.schema.id_fields()
        if not targets:
            logger.info("bola_no_id_fields")
            return []

        logger.info("bola_targets", count=len(targets))
        tasks = [self._probe_field(ctx, field) for field in targets]
        nested = await asyncio.gather(*tasks)
        return [f for batch in nested for f in batch]

    async def _probe_field(self, ctx: RunContext, field: GraphQLField) -> list[Finding]:
        req = ctx.requester
        id_args = [a for a in field.args if a.type_name in {"ID", "ID!", "Int", "Int!"}]
        if not id_args:
            return []

        arg = id_args[0]
        findings: list[Finding] = []

        # Baseline: use an ID that should produce a valid-but-empty response
        invalid_id = "99999999"
        baseline_body = await self._fetch(req, field.name, arg.name, invalid_id)

        data_responses: list[tuple[str, str]] = []

        for probe_id in _PROBE_IDS:
            body = await self._fetch(req, field.name, arg.name, probe_id)
            if body and _looks_like_data(body) and _bodies_differ(baseline_body or "", body):
                data_responses.append((probe_id, body))

        if len(data_responses) >= 2:
            # Multiple IDs return distinct data — classic IDOR
            ids_str = ", ".join(r[0] for r in data_responses[:3])
            findings.append(
                self.finding(
                    title=f"BOLA / IDOR — {field.name}",
                    severity="high",
                    description=(
                        f"The field '{field.name}' returns object data for multiple "
                        f"sequential IDs ({ids_str}) without apparent authorization "
                        f"enforcement. An attacker can enumerate all objects by "
                        f"iterating IDs, potentially accessing other users' data."
                    ),
                    endpoint=ctx.url,
                    payload=f"{field.name}({arg.name}: <ID>)",
                    evidence=(
                        f"IDs {ids_str} each returned distinct non-null data. "
                        f"Sample for ID {data_responses[0][0]}: "
                        f"{truncate(data_responses[0][1], 300)}"
                    ),
                    remediation=(
                        "Enforce object-level authorization on every resolver that accepts "
                        "an ID. Verify the requesting user owns or has explicit access to "
                        "the requested resource. Use opaque non-sequential identifiers (UUIDs)."
                    ),
                )
            )
        elif len(data_responses) == 1:
            probe_id, body = data_responses[0]
            findings.append(
                self.finding(
                    title=f"Potential BOLA — {field.name} (single probe hit)",
                    severity="medium",
                    description=(
                        f"Probing '{field.name}' with ID '{probe_id}' returned non-null "
                        f"data while an invalid ID returned nothing. Manual verification "
                        f"is needed to confirm whether authorization checks are enforced."
                    ),
                    endpoint=ctx.url,
                    payload=f'{field.name}({arg.name}: "{probe_id}")',
                    evidence=truncate(body, 300),
                    remediation=(
                        "Verify that object-level authorization is applied to this resolver. "
                        "The resolver must confirm the caller is permitted to access the "
                        "specific object with that ID."
                    ),
                )
            )

        return findings

    async def _fetch(self, req: object, field: str, arg: str, value: str) -> str | None:
        query = f'{{ {field}({arg}: "{value}") }}'
        try:
            resp = await req.graphql(query)  # type: ignore[union-attr]
            return resp.text
        except (RequestError, AttributeError):
            return None
