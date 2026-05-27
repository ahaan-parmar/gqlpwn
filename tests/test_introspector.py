"""Unit tests for the introspection + parser pipeline."""

from __future__ import annotations

import pytest

from gqlpwn.core.parser import SchemaParser
from gqlpwn.utils.models import GraphQLSchema


# ---------------------------------------------------------------------------
# Sample introspection response (trimmed)
# ---------------------------------------------------------------------------

SAMPLE_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "description": None,
                    "fields": [
                        {
                            "name": "user",
                            "description": "Get a user by ID",
                            "args": [
                                {
                                    "name": "id",
                                    "description": None,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": None,
                                        "ofType": {"kind": "SCALAR", "name": "ID", "ofType": None},
                                    },
                                    "defaultValue": None,
                                }
                            ],
                            "type": {
                                "kind": "OBJECT",
                                "name": "User",
                                "ofType": None,
                            },
                            "isDeprecated": False,
                            "deprecationReason": None,
                        },
                        {
                            "name": "posts",
                            "description": None,
                            "args": [],
                            "type": {
                                "kind": "LIST",
                                "name": None,
                                "ofType": {"kind": "OBJECT", "name": "Post", "ofType": None},
                            },
                            "isDeprecated": False,
                            "deprecationReason": None,
                        },
                    ],
                    "inputFields": None,
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "description": None,
                    "fields": [
                        {
                            "name": "createPost",
                            "description": None,
                            "args": [
                                {
                                    "name": "title",
                                    "description": None,
                                    "type": {
                                        "kind": "NON_NULL",
                                        "name": None,
                                        "ofType": {"kind": "SCALAR", "name": "String", "ofType": None},
                                    },
                                    "defaultValue": None,
                                }
                            ],
                            "type": {"kind": "OBJECT", "name": "Post", "ofType": None},
                            "isDeprecated": False,
                            "deprecationReason": None,
                        }
                    ],
                    "inputFields": None,
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "description": None,
                    "fields": [
                        {
                            "name": "id",
                            "description": None,
                            "args": [],
                            "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                            "isDeprecated": False,
                            "deprecationReason": None,
                        },
                        {
                            "name": "email",
                            "description": None,
                            "args": [],
                            "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                            "isDeprecated": False,
                            "deprecationReason": None,
                        },
                    ],
                    "inputFields": None,
                    "interfaces": [],
                    "enumValues": None,
                    "possibleTypes": None,
                },
            ],
            "directives": [],
        }
    }
}


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestSchemaParser:
    def setup_method(self) -> None:
        self.parser = SchemaParser()

    def test_parses_queries(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        assert len(schema.queries) == 2
        names = {f.name for f in schema.queries}
        assert "user" in names
        assert "posts" in names

    def test_parses_mutations(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        assert len(schema.mutations) == 1
        assert schema.mutations[0].name == "createPost"

    def test_no_subscriptions(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        assert schema.subscriptions == []

    def test_query_argument_types(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        user_field = next(f for f in schema.queries if f.name == "user")
        assert len(user_field.args) == 1
        assert user_field.args[0].name == "id"
        assert user_field.args[0].type_name == "ID!"
        assert user_field.args[0].is_required is True

    def test_mutation_string_arg(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        create = schema.mutations[0]
        assert create.args[0].type_name == "String!"

    def test_list_type_resolution(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        posts = next(f for f in schema.queries if f.name == "posts")
        assert posts.field_type == "[Post]"

    def test_types_dict_excludes_builtins(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        # Query and Mutation are operation roots, not custom types worth keeping separate
        for type_name in schema.types:
            assert not type_name.startswith("__")
            assert type_name not in {"String", "Int", "Float", "Boolean", "ID"}

    def test_injectable_fields(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        # createPost has a String! arg → should be injectable
        injectable = schema.injectable_fields()
        assert any(f.name == "createPost" for f in injectable)

    def test_id_fields(self) -> None:
        schema = self.parser.parse(SAMPLE_INTROSPECTION)
        id_fields = schema.id_fields()
        assert any(f.name == "user" for f in id_fields)

    def test_empty_response_returns_empty_schema(self) -> None:
        schema = self.parser.parse({})
        assert isinstance(schema, GraphQLSchema)
        assert schema.queries == []

    def test_wordlist_schema(self) -> None:
        raw = {"_method": "wordlist", "wordlist_discovered": ["user", "posts", "admin"]}
        schema = self.parser.parse(raw)
        assert len(schema.queries) == 3
        assert schema.discovery_method == "wordlist"


# ---------------------------------------------------------------------------
# Model helper tests
# ---------------------------------------------------------------------------

class TestGraphQLFieldHelpers:
    def test_has_string_args(self) -> None:
        from gqlpwn.utils.models import GraphQLArgument, GraphQLField
        f = GraphQLField(
            name="search",
            field_type="[Result]",
            args=[GraphQLArgument(name="query", type_name="String!")],
        )
        assert f.has_string_args() is True

    def test_has_id_args(self) -> None:
        from gqlpwn.utils.models import GraphQLArgument, GraphQLField
        f = GraphQLField(
            name="getUser",
            field_type="User",
            args=[GraphQLArgument(name="id", type_name="ID!")],
        )
        assert f.has_id_args() is True

    def test_has_url_args(self) -> None:
        from gqlpwn.utils.models import GraphQLArgument, GraphQLField
        f = GraphQLField(
            name="fetchRemote",
            field_type="String",
            args=[GraphQLArgument(name="url", type_name="String!")],
        )
        assert f.has_url_args() is True


# ---------------------------------------------------------------------------
# Scorer tests
# ---------------------------------------------------------------------------

class TestScorer:
    def test_critical_score(self) -> None:
        from gqlpwn.core.scorer import score
        from gqlpwn.utils.models import Finding
        f = Finding(
            title="SQL Injection", severity="critical",
            description="", endpoint="", module="injection",
            evidence="", remediation="",
        )
        assert score(f) >= 9.0

    def test_info_score(self) -> None:
        from gqlpwn.core.scorer import score
        from gqlpwn.utils.models import Finding
        f = Finding(
            title="Version Disclosed", severity="info",
            description="", endpoint="", module="info_disclosure",
            evidence="", remediation="",
        )
        assert score(f) == 0.0
