"""GraphQL schema discovery via introspection with multi-strategy fallback."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from gqlpwn.core.requester import RequestError, Requester
from gqlpwn.utils.helpers import load_wordlist
from gqlpwn.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Introspection queries
# ---------------------------------------------------------------------------

FULL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType { kind name }
            }
          }
        }
      }
    }
  }
}
""".strip()

# Lightweight probe — just confirms the endpoint speaks GraphQL
PROBE_QUERY = "{ __typename }"

# Partial introspection — works even when full introspection is partially disabled
PARTIAL_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

# Headers that sometimes bypass introspection blockers
_BYPASS_HEADER_SETS: list[dict[str, str]] = [
    {"Origin": "https://studio.apollographql.com"},
    {"Referer": "https://localhost:3000/graphql"},
    {"X-Apollo-Studio-Init": "1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
]

_SUGGESTION_RE = re.compile(r'Did you mean "([^"]+)"')


@dataclass
class IntrospectionResult:
    raw: dict[str, Any]
    method: str          # full | bypass | partial | wordlist | none
    enabled: bool


class Introspector:
    """
    Discovers a GraphQL schema through multiple strategies:

    1. Standard full introspection query
    2. Common header-based bypass techniques
    3. Partial schema probe (__schema root fields only)
    4. Wordlist-driven field guessing via suggestion extraction
    """

    def __init__(self, requester: Requester, wordlist_path: str | None = None) -> None:
        self.requester = requester
        self.wordlist = load_wordlist(wordlist_path)

    async def run(self) -> IntrospectionResult:
        logger.info("introspection_start", url=self.requester.config.url)

        # 1. Full introspection
        raw = await self._full_introspection()
        if raw:
            logger.info("introspection_success", method="full")
            return IntrospectionResult(raw=raw, method="full", enabled=True)

        # 2. Bypass via modified headers
        for headers in _BYPASS_HEADER_SETS:
            raw = await self._full_introspection(extra_headers=headers)
            if raw:
                logger.info("introspection_success", method="bypass", via=list(headers.keys()))
                return IntrospectionResult(raw=raw, method="bypass", enabled=True)

        # 3. Partial schema probe
        raw = await self._partial_introspection()
        if raw:
            logger.warning("introspection_partial")
            return IntrospectionResult(raw=raw, method="partial", enabled=True)

        # 4. Wordlist field discovery
        logger.warning("introspection_disabled_falling_back_to_wordlist")
        discovered = await self._wordlist_discovery()
        if discovered:
            return IntrospectionResult(raw=discovered, method="wordlist", enabled=False)

        logger.error("schema_discovery_failed")
        return IntrospectionResult(raw={}, method="none", enabled=False)

    # ------------------------------------------------------------------ #
    # Strategies
    # ------------------------------------------------------------------ #

    async def _full_introspection(
        self,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        try:
            resp = await self.requester.graphql(
                FULL_INTROSPECTION_QUERY,
                extra_headers=extra_headers,
            )
            if resp.status_code not in (200, 400):
                return None
            data = self.requester.parse_json(resp)
            if data and isinstance(data.get("data"), dict) and "__schema" in data["data"]:
                return data
        except RequestError as exc:
            logger.debug("full_introspection_failed", error=str(exc))
        return None

    async def _partial_introspection(self) -> dict[str, Any] | None:
        try:
            resp = await self.requester.graphql(PARTIAL_QUERY)
            data = self.requester.parse_json(resp)
            if data and isinstance(data.get("data"), dict):
                return data
        except RequestError:
            pass
        return None

    async def _wordlist_discovery(self) -> dict[str, Any]:
        """
        Probe each word in the wordlist as a top-level Query field.
        Collect fields the server confirms exist (no "Cannot query field" error)
        or that trigger "Did you mean X?" suggestions we can harvest.
        """
        discovered: list[str] = []

        for field in self.wordlist:
            query = f"{{ {field} }}"
            try:
                resp = await self.requester.graphql(query)
                body = resp.text

                if "Cannot query field" not in body:
                    discovered.append(field)
                    logger.debug("wordlist_field_found", field=field)
                else:
                    suggestions = _SUGGESTION_RE.findall(body)
                    for s in suggestions:
                        if s not in discovered:
                            discovered.append(s)
                            logger.debug("wordlist_suggestion", field=s)
            except RequestError:
                pass

        return {"_method": "wordlist", "wordlist_discovered": discovered}
