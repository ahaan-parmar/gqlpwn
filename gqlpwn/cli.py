"""
gqlpwn CLI — GraphQL Security Testing Framework
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from gqlpwn import __version__
from gqlpwn.utils.helpers import parse_cookies, parse_headers
from gqlpwn.utils.logger import configure_logging

console = Console()

_BANNER = f"""[bold cyan]
  __ _ __ _ | _ \\ __ \\  \\ \\  / /  \\  |
 / _` |/ _` | |_) |  ) |  \\ \\/ /  |\\  |
| (_| | (_| |  __/  __/    \\  /   | \\ |
 \\__, |\\__, |_|  |_|        \\/   _|  \\_|
 |___/ |___/
[/bold cyan]
[dim]  GraphQL Security Testing Framework  v{__version__}[/dim]
[dim]  For authorized assessments only.[/dim]
"""

AVAILABLE_MODULES = [
    "info_disclosure",
    "injection",
    "bola",
    "auth",
    "dos",
    "ssrf",
]


def _print_banner() -> None:
    console.print(_BANNER)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, "-V", "--version", prog_name="gqlpwn")
def cli() -> None:
    """gqlpwn — GraphQL Security Testing Framework."""


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-u", "--url",          required=True,  help="Target GraphQL endpoint URL")
@click.option("-H", "--header",       multiple=True,  help="HTTP header (repeatable): 'Authorization: Bearer TOKEN'")
@click.option("-c", "--cookie",       default=None,   help="Cookie string: 'session=abc; csrf=xyz'")
@click.option("-x", "--proxy",        default=None,   help="HTTP/HTTPS proxy URL: 'http://127.0.0.1:8080'")
@click.option("-m", "--modules",      default=None,   help=f"Comma-separated modules [{', '.join(AVAILABLE_MODULES)}]")
@click.option("-o", "--output",       default=None,   help="Output file path (e.g., report.html)")
@click.option("-f", "--format",       default="html", type=click.Choice(["html", "json", "markdown"]), help="Output format")
@click.option("-t", "--timeout",      default=30,     type=int, help="Request timeout in seconds")
@click.option("-w", "--workers",      default=10,     type=int, help="Max concurrent requests")
@click.option("-r", "--rate-limit",   default=0.0,    type=float, help="Seconds between requests (0=unlimited)")
@click.option("--wordlist",           default=None,   help="Custom field wordlist for blind discovery")
@click.option("--aggressive",         is_flag=True,   help="Enable aggressive modules (dos)")
@click.option("-v", "--verbose",      is_flag=True,   help="Verbose output")
@click.option("--config",             default=None,   help="Path to config.yaml")
def scan(
    url: str,
    header: tuple[str, ...],
    cookie: str | None,
    proxy: str | None,
    modules: str | None,
    output: str | None,
    format: str,
    timeout: int,
    workers: int,
    rate_limit: float,
    wordlist: str | None,
    aggressive: bool,
    verbose: bool,
    config: str | None,
) -> None:
    """Run a full GraphQL security scan against a target endpoint."""
    _print_banner()
    configure_logging(verbose)

    from gqlpwn.core.scanner import Scanner
    from gqlpwn.output.reporter import Reporter
    from gqlpwn.utils.config import load_config
    from gqlpwn.utils.models import ScanConfig

    cfg_file = load_config(config)

    selected_modules = [m.strip() for m in modules.split(",")] if modules else []

    scan_config = ScanConfig(
        url=url,
        headers=parse_headers(header),
        cookies=parse_cookies(cookie),
        proxy=proxy,
        timeout=timeout,
        concurrency=workers,
        rate_limit=rate_limit,
        verbose=verbose,
        aggressive=aggressive,
        modules=selected_modules,
        output_file=output,
        output_format=format,
        wordlist=wordlist,
        max_depth=cfg_file.get("max_depth", 3),
    )

    if aggressive:
        console.print("[bold yellow]⚠ Aggressive mode enabled — DoS-category modules are active.[/]")
        console.print("[dim]  Only use against systems you own or have explicit written permission to test.[/]\n")

    result = asyncio.run(Scanner(scan_config).run())

    if output:
        reporter = Reporter(result)
        reporter.write(output, format)  # type: ignore[arg-type]
        console.print(f"\n[green]Report written to [bold]{output}[/bold][/]")
    else:
        # Print findings to stdout if no output file
        _print_findings_table(result)


# ---------------------------------------------------------------------------
# introspect command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("-u", "--url",    required=True,  help="Target GraphQL endpoint")
@click.option("-H", "--header", multiple=True,  help="HTTP header")
@click.option("-x", "--proxy",  default=None)
@click.option("-t", "--timeout",default=30, type=int)
@click.option("-o", "--output", default=None,   help="Write schema JSON to file")
@click.option("-v", "--verbose",is_flag=True)
def introspect(
    url: str,
    header: tuple[str, ...],
    proxy: str | None,
    timeout: int,
    output: str | None,
    verbose: bool,
) -> None:
    """Run schema discovery only and print or save the result."""
    _print_banner()
    configure_logging(verbose)

    import json as _json

    from gqlpwn.core.introspector import Introspector
    from gqlpwn.core.parser import SchemaParser
    from gqlpwn.core.requester import Requester
    from gqlpwn.utils.models import ScanConfig

    config = ScanConfig(
        url=url,
        headers=parse_headers(header),
        proxy=proxy,
        timeout=timeout,
    )

    async def _run() -> None:
        async with Requester(config) as req:
            intro = Introspector(req)
            result = await intro.run()
            parser = SchemaParser()
            schema = parser.parse(result.raw)

            console.print(f"\nDiscovery method : [bold]{result.method}[/]")
            console.print(f"Introspection    : [bold]{'enabled' if result.enabled else 'disabled'}[/]")
            console.print(f"Queries          : {len(schema.queries)}")
            console.print(f"Mutations        : {len(schema.mutations)}")
            console.print(f"Subscriptions    : {len(schema.subscriptions)}")
            console.print(f"Types            : {len(schema.types)}")

            if schema.queries:
                console.print("\n[bold]Query fields:[/]")
                for f in schema.queries[:30]:
                    args = ", ".join(f"{a.name}: {a.type_name}" for a in f.args)
                    console.print(f"  [cyan]{f.name}[/]({args}): {f.field_type}")
                if len(schema.queries) > 30:
                    console.print(f"  … and {len(schema.queries) - 30} more")

            if output:
                Path(output).write_text(_json.dumps(result.raw, indent=2), encoding="utf-8")
                console.print(f"\n[green]Schema written to {output}[/]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# list-modules command
# ---------------------------------------------------------------------------

@cli.command("list-modules")
def list_modules() -> None:
    """List all available vulnerability modules."""
    _print_banner()

    from gqlpwn.core.scanner import MODULE_REGISTRY, _import_module_class

    table = Table(title="Available Modules", header_style="bold cyan", show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Aggressive?", justify="center")

    for name, dotted in MODULE_REGISTRY.items():
        try:
            cls = _import_module_class(dotted)
            inst = cls()
            agg = "[red]Yes[/]" if inst.metadata.requires_aggressive else "No"
            table.add_row(name, inst.description, agg)
        except Exception as exc:
            table.add_row(name, f"[red]Load error: {exc}[/]", "?")

    console.print(table)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_findings_table(result: object) -> None:
    from gqlpwn.utils.models import ScanResult
    r: ScanResult = result  # type: ignore[assignment]
    if not r.findings:
        console.print("\n[green]No findings.[/]")
        return

    table = Table(title="Findings", show_lines=True, header_style="bold magenta")
    table.add_column("Sev", width=8)
    table.add_column("Title", ratio=3)
    table.add_column("Module", ratio=1)
    table.add_column("CVSS", justify="right", width=6)

    colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "dim"}
    for f in r.findings:
        c = colors.get(f.severity, "white")
        table.add_row(
            f"[{c}]{f.severity.upper()}[/]",
            f.title,
            f.module,
            f"[{c}]{f.cvss_score:.1f}[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
