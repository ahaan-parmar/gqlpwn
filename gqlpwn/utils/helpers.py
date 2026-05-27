"""Utility helpers used across the framework."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PAYLOADS_DIR = Path(__file__).parent.parent / "payloads"

# Built-in wordlist for field name discovery when introspection is disabled
BUILTIN_WORDLIST: list[str] = [
    "user", "users", "me", "viewer", "account", "accounts",
    "profile", "profiles", "post", "posts", "article", "articles",
    "comment", "comments", "product", "products", "order", "orders",
    "admin", "admins", "login", "logout", "register", "signup",
    "token", "refresh", "verify", "reset", "password", "email",
    "search", "filter", "list", "get", "create", "update", "delete",
    "upload", "download", "file", "files", "image", "images",
    "message", "messages", "notification", "notifications",
    "setting", "settings", "config", "configuration",
    "role", "roles", "permission", "permissions", "group", "groups",
    "team", "teams", "organization", "project", "projects",
    "report", "reports", "audit", "logs", "analytics",
    "health", "status", "version", "info", "ping",
    "payment", "payments", "invoice", "invoices", "billing",
    "customer", "customers", "vendor", "vendors",
    "category", "categories", "tag", "tags", "label", "labels",
    "node", "nodes", "edge", "edges", "connection",
    "mutation", "query", "subscription",
    "createUser", "updateUser", "deleteUser",
    "getUser", "getUserById", "listUsers",
]


def load_wordlist(custom_path: str | None = None) -> list[str]:
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]
    return BUILTIN_WORDLIST


def load_payload_file(filename: str) -> dict[str, Any]:
    path = PAYLOADS_DIR / filename
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"payloads": [], "error_signatures": []}


def parse_headers(header_strings: tuple[str, ...] | list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for h in header_strings:
        if ":" in h:
            key, _, value = h.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def parse_cookies(cookie_str: str | None) -> dict[str, str]:
    if not cookie_str:
        return {}
    cookies: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            cookies[key.strip()] = value.strip()
    return cookies


def truncate(text: str, max_len: int = 500) -> str:
    return text if len(text) <= max_len else text[:max_len] + "…"


def contains_any(text: str, signatures: list[str], case_sensitive: bool = False) -> str | None:
    """Return the first matching signature, or None."""
    haystack = text if case_sensitive else text.lower()
    for sig in signatures:
        needle = sig if case_sensitive else sig.lower()
        if needle in haystack:
            return sig
    return None


def extract_suggestions(body: str) -> list[str]:
    """Pull field-name suggestions out of a GraphQL 'Did you mean X?' error."""
    return re.findall(r'Did you mean "([^"]+)"', body)


def build_gql_query(field: str, args: dict[str, Any] | None = None, selection: str = "__typename") -> str:
    """Construct a minimal GraphQL query string for a given field."""
    if args:
        arg_str = ", ".join(f'{k}: {json.dumps(v)}' for k, v in args.items())
        return f"{{ {field}({arg_str}) {{ {selection} }} }}"
    return f"{{ {field} {{ {selection} }} }}"


def is_json_response(content_type: str) -> bool:
    return "application/json" in content_type or "application/graphql" in content_type
