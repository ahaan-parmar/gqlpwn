"""Structured logging via Rich."""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)
_configured = False


def configure_logging(verbose: bool = False) -> None:
    global _configured
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=_console,
                show_path=verbose,
                markup=True,
                rich_tracebacks=True,
                tracebacks_show_locals=verbose,
            )
        ],
        force=True,
    )
    _configured = True


class StructuredLogger:
    """Wraps stdlib logger with key=value structured output."""

    def __init__(self, name: str) -> None:
        self._log = logging.getLogger(name)

    def _fmt(self, msg: str, **kv: Any) -> str:
        if not kv:
            return msg
        pairs = " ".join(f"{k}={v!r}" for k, v in kv.items())
        return f"{msg} {pairs}"

    def debug(self, msg: str, **kv: Any) -> None:
        self._log.debug(self._fmt(msg, **kv))

    def info(self, msg: str, **kv: Any) -> None:
        self._log.info(self._fmt(msg, **kv))

    def warning(self, msg: str, **kv: Any) -> None:
        self._log.warning(self._fmt(msg, **kv))

    def error(self, msg: str, **kv: Any) -> None:
        self._log.error(self._fmt(msg, **kv))

    def critical(self, msg: str, **kv: Any) -> None:
        self._log.critical(self._fmt(msg, **kv))


def get_logger(name: str) -> StructuredLogger:
    if not _configured:
        configure_logging()
    return StructuredLogger(name)
