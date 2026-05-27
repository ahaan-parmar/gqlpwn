"""
Reporting engine — renders ScanResult into JSON, Markdown, or HTML.
Uses Jinja2 for HTML/Markdown output.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

from gqlpwn.utils.models import ScanResult

OutputFormat = Literal["json", "markdown", "html"]

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["severity_color"] = _severity_color
    env.filters["fmt_date"] = lambda dt: dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"
    return env


def _severity_color(severity: str) -> str:
    return {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#2563eb",
        "info":     "#6b7280",
    }.get(severity, "#374151")


def _severity_badge_class(severity: str) -> str:
    return {
        "critical": "badge-critical",
        "high":     "badge-high",
        "medium":   "badge-medium",
        "low":      "badge-low",
        "info":     "badge-info",
    }.get(severity, "badge-info")


class Reporter:
    """Renders a ScanResult to the requested format."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result

    def render(self, fmt: OutputFormat) -> str:
        if fmt == "json":
            return self._render_json()
        if fmt == "markdown":
            return self._render_markdown()
        if fmt == "html":
            return self._render_html()
        raise ValueError(f"Unknown format: {fmt}")

    def write(self, path: str, fmt: OutputFormat) -> None:
        content = self.render(fmt)
        out = Path(path)
        out.write_text(content, encoding="utf-8")

    # ------------------------------------------------------------------ #

    def _render_json(self) -> str:
        return self.result.model_dump_json(indent=2, exclude={"schema": {"raw"}})

    def _render_markdown(self) -> str:
        env = _jinja_env()
        tmpl = env.get_template("report.md.j2")
        return tmpl.render(
            result=self.result,
            by_severity=self.result.findings_by_severity(),
            generated_at=datetime.utcnow(),
        )

    def _render_html(self) -> str:
        env = _jinja_env()
        env.filters["severity_badge_class"] = _severity_badge_class
        tmpl = env.get_template("report.html.j2")
        return tmpl.render(
            result=self.result,
            by_severity=self.result.findings_by_severity(),
            generated_at=datetime.utcnow(),
        )
