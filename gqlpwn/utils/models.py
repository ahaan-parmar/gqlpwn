"""Core data models for gqlpwn."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]


class GraphQLArgument(BaseModel):
    name: str
    type_name: str
    is_required: bool = False
    default_value: str | None = None
    description: str | None = None


class GraphQLField(BaseModel):
    name: str
    field_type: str
    args: list[GraphQLArgument] = Field(default_factory=list)
    requires_auth: bool | None = None
    is_deprecated: bool = False
    deprecation_reason: str | None = None
    description: str | None = None

    def has_string_args(self) -> bool:
        """Return True if any argument accepts a string-like value."""
        string_types = {"String", "ID", "String!", "ID!"}
        return any(a.type_name in string_types for a in self.args)

    def has_id_args(self) -> bool:
        """Return True if any argument is an ID type."""
        id_types = {"ID", "ID!", "Int", "Int!"}
        return any(a.type_name in id_types for a in self.args)

    def has_url_args(self) -> bool:
        """Return True if any argument name suggests it holds a URL."""
        url_hints = {"url", "uri", "endpoint", "link", "href", "src", "source", "webhook", "callback"}
        return any(a.name.lower() in url_hints for a in self.args)


class GraphQLType(BaseModel):
    name: str
    kind: str  # OBJECT | SCALAR | ENUM | INPUT_OBJECT | INTERFACE | UNION
    fields: list[GraphQLField] = Field(default_factory=list)
    enum_values: list[str] = Field(default_factory=list)
    description: str | None = None


class GraphQLSchema(BaseModel):
    queries: list[GraphQLField] = Field(default_factory=list)
    mutations: list[GraphQLField] = Field(default_factory=list)
    subscriptions: list[GraphQLField] = Field(default_factory=list)
    types: dict[str, GraphQLType] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    discovery_method: str = "full"  # full | bypass | partial | wordlist | none

    def all_operations(self) -> list[GraphQLField]:
        return self.queries + self.mutations + self.subscriptions

    def injectable_fields(self) -> list[GraphQLField]:
        return [f for f in self.all_operations() if f.has_string_args()]

    def id_fields(self) -> list[GraphQLField]:
        return [f for f in self.all_operations() if f.has_id_args()]

    def url_fields(self) -> list[GraphQLField]:
        return [f for f in self.all_operations() if f.has_url_args()]


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: SeverityLevel
    cvss_score: float = 0.0
    description: str
    endpoint: str
    module: str
    payload: str | None = None
    evidence: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_response: str | None = None

    @property
    def severity_emoji(self) -> str:
        return {
            "critical": "[red]CRIT[/red]",
            "high": "[bright_red]HIGH[/bright_red]",
            "medium": "[yellow]MED[/yellow]",
            "low": "[blue]LOW[/blue]",
            "info": "[dim]INFO[/dim]",
        }[self.severity]


class ScanConfig(BaseModel):
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    proxy: str | None = None
    timeout: int = 30
    concurrency: int = 10
    verbose: bool = False
    aggressive: bool = False
    modules: list[str] = Field(default_factory=list)
    output_file: str | None = None
    output_format: str = "html"
    wordlist: str | None = None
    max_depth: int = 3
    rate_limit: float = 0.0


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    gql_schema: GraphQLSchema | None = None
    modules_run: list[str] = Field(default_factory=list)
    introspection_enabled: bool = False
    error: str | None = None

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


@dataclass
class RunContext:
    """Runtime context passed into every module during a scan.

    Separates serializable scan state (ScanConfig, ScanResult) from
    the live HTTP client (Requester) which cannot be serialized.
    """
    config: ScanConfig
    result: ScanResult
    requester: Any  # Requester — typed as Any to avoid circular import

    @property
    def url(self) -> str:
        return self.config.url

    @property
    def schema(self) -> GraphQLSchema | None:
        return self.result.gql_schema

    @property
    def verbose(self) -> bool:
        return self.config.verbose

    @property
    def aggressive(self) -> bool:
        return self.config.aggressive
