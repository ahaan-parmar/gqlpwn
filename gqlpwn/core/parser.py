"""Convert raw GraphQL introspection JSON into structured internal models."""

from __future__ import annotations

from typing import Any

from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import (
    GraphQLArgument,
    GraphQLField,
    GraphQLSchema,
    GraphQLType,
)

logger = get_logger(__name__)

# Types that are implementation details, not application schema
_BUILTIN_PREFIXES = ("__",)
_BUILTIN_SCALARS = frozenset(
    {"String", "Int", "Float", "Boolean", "ID"}
)


def _resolve_type(ref: dict[str, Any] | None, depth: int = 0) -> str:
    """Recursively flatten a TypeRef object into a human-readable string.

    Example outputs: 'String!', '[User!]!', 'ID'
    """
    if ref is None or depth > 10:
        return "Unknown"
    kind = ref.get("kind", "")
    name = ref.get("name")
    of_type = ref.get("ofType")

    if kind == "NON_NULL":
        return f"{_resolve_type(of_type, depth + 1)}!"
    if kind == "LIST":
        return f"[{_resolve_type(of_type, depth + 1)}]"
    return name or "Unknown"


def _parse_argument(raw: dict[str, Any]) -> GraphQLArgument:
    type_name = _resolve_type(raw.get("type"))
    return GraphQLArgument(
        name=raw.get("name", ""),
        type_name=type_name,
        is_required=type_name.endswith("!"),
        default_value=raw.get("defaultValue"),
        description=raw.get("description"),
    )


def _parse_field(raw: dict[str, Any]) -> GraphQLField:
    return GraphQLField(
        name=raw.get("name", ""),
        field_type=_resolve_type(raw.get("type")),
        args=[_parse_argument(a) for a in (raw.get("args") or [])],
        is_deprecated=raw.get("isDeprecated", False),
        deprecation_reason=raw.get("deprecationReason"),
        description=raw.get("description"),
    )


def _is_builtin(name: str) -> bool:
    return name in _BUILTIN_SCALARS or any(name.startswith(p) for p in _BUILTIN_PREFIXES)


class SchemaParser:
    """
    Converts a raw introspection response dict into a GraphQLSchema.
    Also handles the synthetic 'wordlist' discovery format.
    """

    def parse(self, raw: dict[str, Any]) -> GraphQLSchema:
        # Wordlist discovery produces a different structure
        if raw.get("_method") == "wordlist":
            return self._parse_wordlist(raw)

        schema_data: dict[str, Any] = (
            raw.get("data", {}) or {}
        ).get("__schema", {}) or {}

        if not schema_data:
            logger.warning("parser_empty_schema")
            return GraphQLSchema(raw=raw)

        query_type = (schema_data.get("queryType") or {}).get("name", "Query")
        mutation_type = (schema_data.get("mutationType") or {}).get("name")
        subscription_type = (schema_data.get("subscriptionType") or {}).get("name")

        queries: list[GraphQLField] = []
        mutations: list[GraphQLField] = []
        subscriptions: list[GraphQLField] = []
        types: dict[str, GraphQLType] = {}

        for type_def in schema_data.get("types") or []:
            name: str = type_def.get("name", "")
            if not name or _is_builtin(name):
                continue

            kind = type_def.get("kind", "OBJECT")
            raw_fields = type_def.get("fields") or []
            raw_enums = type_def.get("enumValues") or []

            parsed_fields = [_parse_field(f) for f in raw_fields]
            enum_values = [ev.get("name", "") for ev in raw_enums]

            gql_type = GraphQLType(
                name=name,
                kind=kind,
                fields=parsed_fields,
                enum_values=enum_values,
                description=type_def.get("description"),
            )
            types[name] = gql_type

            if name == query_type:
                queries = parsed_fields
            elif mutation_type and name == mutation_type:
                mutations = parsed_fields
            elif subscription_type and name == subscription_type:
                subscriptions = parsed_fields

        schema = GraphQLSchema(
            queries=queries,
            mutations=mutations,
            subscriptions=subscriptions,
            types=types,
            raw=raw,
            discovery_method="full",
        )
        logger.info(
            "schema_parsed",
            queries=len(queries),
            mutations=len(mutations),
            subscriptions=len(subscriptions),
            types=len(types),
        )
        return schema

    def _parse_wordlist(self, raw: dict[str, Any]) -> GraphQLSchema:
        """Build a minimal schema from wordlist-discovered field names."""
        fields = [
            GraphQLField(name=name, field_type="Unknown")
            for name in raw.get("wordlist_discovered", [])
        ]
        logger.info("schema_from_wordlist", fields=len(fields))
        return GraphQLSchema(queries=fields, raw=raw, discovery_method="wordlist")
