"""Configuration loading — YAML file merged with hard defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from gqlpwn.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULTS: dict[str, Any] = {
    "timeout": 30,
    "concurrency": 10,
    "max_retries": 3,
    "rate_limit": 0.0,
    "max_depth": 3,
    "verify_ssl": False,
    "follow_redirects": True,
    "user_agent": "gqlpwn/1.0 (GraphQL Security Scanner)",
    "dos_max_depth": 15,
    "dos_max_aliases": 100,
    "dos_max_batch": 50,
    "id_range": 10,
}

_SEARCH_PATHS = [
    "config.yaml",
    "config.yml",
    str(Path.home() / ".config" / "gqlpwn" / "config.yaml"),
]


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load YAML config, merging user values over defaults."""
    cfg = DEFAULTS.copy()
    candidates = ([path] if path else []) + _SEARCH_PATHS

    for candidate in candidates:
        if not candidate:
            continue
        p = Path(candidate)
        if p.exists():
            try:
                with p.open() as f:
                    user = yaml.safe_load(f) or {}
                # Flatten nested sections (http.timeout -> timeout)
                for section in ("http", "scan", "dos", "output", "logging"):
                    if section in user and isinstance(user[section], dict):
                        cfg.update(user.pop(section))
                cfg.update(user)
                logger.debug("config_loaded", path=str(p))
                break
            except yaml.YAMLError as exc:
                logger.warning("config_parse_error", path=str(p), error=str(exc))

    return cfg
