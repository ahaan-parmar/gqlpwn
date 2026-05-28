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
@click.argument("url")
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
        console.print("[bold yellow]! Aggressive mode enabled -- DoS-category modules are active.[/]")
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
@click.argument("url")
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
# autopwn command
# ---------------------------------------------------------------------------

async def _autopwn_pipeline(
    url: str,
    token: str,
    proxy: str | None,
    timeout: int,
    workers: int,
    mutations: bool,
    aggressive: bool,
    output: str,
    fmt: str,
    extra_headers: dict | None = None,
) -> None:
    """Shared autopwn pipeline used by both `autopwn` and `fullpwn` commands."""
    import json as _json
    from rich.rule import Rule
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

    from gqlpwn.core.context_discoverer import ContextDiscoverer
    from gqlpwn.core.enumerator import Enumerator
    from gqlpwn.core.introspector import Introspector
    from gqlpwn.core.parser import SchemaParser
    from gqlpwn.core.requester import Requester
    from gqlpwn.core.scanner import Scanner, _resolve_modules
    from gqlpwn.core.scorer import assign_scores
    from gqlpwn.modules.tenant_isolation import TenantIsolationModule
    from gqlpwn.output.reporter import Reporter
    from gqlpwn.utils.models import RunContext, ScanConfig, ScanResult

    config = ScanConfig(
        url=url,
        headers={"Authorization": token, **(extra_headers or {})},
        proxy=proxy,
        timeout=timeout,
        concurrency=workers,
        aggressive=aggressive,
    )

    async with Requester(config) as req:

        # ── Phase 1: Schema ──────────────────────────────────────────
        console.print(Rule("[bold cyan]Phase 1 -- Schema Discovery[/]"))
        with console.status("Pulling schema..."):
            intro = Introspector(req)
            intro_result = await intro.run()
        schema = SchemaParser().parse(intro_result.raw)
        console.print(
            f"  Introspection : [bold]{'enabled' if intro_result.enabled else 'DISABLED'}[/]"
        )
        console.print(f"  Queries       : [bold]{len(schema.queries)}[/]")
        console.print(f"  Mutations     : [bold]{len(schema.mutations)}[/]")
        console.print(f"  Types         : [bold]{len(schema.types)}[/]")

        # ── Phase 2: Context Discovery ───────────────────────────────
        console.print(Rule("[bold cyan]Phase 2 -- Context Discovery[/]"))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
            transient=True,
        ) as progress:
            probe_task = progress.add_task("Probing queries for user/org context...", total=None)

            def _on_probe(probed: int, total: int) -> None:
                progress.update(probe_task, completed=probed, total=total)

            discoverer = ContextDiscoverer(req, token, on_probe=_on_probe)
            ctx_info = await discoverer.discover(schema)

        console.print(ctx_info.summary())
        if ctx_info.discovery_log:
            for entry in ctx_info.discovery_log:
                console.print(f"  [dim]>> {entry}[/]")

        # ── Phase 3: Enumeration ─────────────────────────────────────
        console.print(Rule("[bold cyan]Phase 3 -- Operation Enumeration[/]"))
        enumerator = Enumerator(req, org_id=ctx_info.org_id, concurrency=workers)
        mut_list = schema.mutations if mutations else []

        with console.status(
            f"Firing {len(schema.queries)} queries"
            + (f" + {len(mut_list)} mutations" if mutations else "") + "..."
        ):
            enum_report = await enumerator.run_all(schema.queries, mut_list, url)

        console.print(f"  Accessible queries   : [green]{len(enum_report.accessible_queries)}[/]")
        console.print(f"  Accessible mutations : [green]{len(enum_report.accessible_mutations)}[/]")
        console.print(f"  Sensitive responses  : [red]{len(enum_report.sensitive_findings)}[/]")
        console.print(f"  Auth-blocked         : [dim]{len(enum_report.auth_blocked)}[/]")

        if enum_report.sensitive_findings:
            console.print("\n  [bold red]Sensitive data detected in:[/]")
            for r in enum_report.sensitive_findings:
                console.print(f"    [red]{r.field_name}[/] -- {', '.join(r.sensitive_matches)}")
                console.print(f"    [dim]{r.response_body[:200]}[/]\n")

        # ── Phase 4: Tenant Isolation ────────────────────────────────
        console.print(Rule("[bold cyan]Phase 4 -- Tenant Isolation (BOLA)[/]"))
        result = ScanResult(target=url)
        result.gql_schema = schema
        result.introspection_enabled = intro_result.enabled
        run_ctx = RunContext(config=config, result=result, requester=req)

        if ctx_info.org_id:
            console.print(f"  Own org_id: [cyan]{ctx_info.org_id}[/]")
            with console.status("Testing cross-tenant access..."):
                iso_mod = TenantIsolationModule(own_org_id=ctx_info.org_id)
                iso_findings = await iso_mod.run(run_ctx)
            if iso_findings:
                console.print(f"  [bold red]CRITICAL: {len(iso_findings)} tenant isolation failure(s)[/]")
                for f in iso_findings:
                    console.print(f"    [red]{f.title}[/]")
            else:
                console.print("  [green]No cross-tenant access confirmed[/]")
            result.findings.extend(iso_findings)
        else:
            console.print("  [yellow]org_id not discovered -- skipping tenant isolation[/]")

        # ── Phase 5: Vulnerability Scan ──────────────────────────────
        console.print(Rule("[bold cyan]Phase 5 -- Vulnerability Modules[/]"))
        vuln_config = config.model_copy(update={
            "modules": ["info_disclosure", "injection", "bola", "auth", "ssrf"]
            + (["dos"] if aggressive else []),
            "aggressive": aggressive,
        })
        mods = _resolve_modules(vuln_config.modules, aggressive)

        module_findings = []
        for mod in mods:
            try:
                mf = await mod.run(run_ctx)
                module_findings.extend(mf)
                if mf:
                    console.print(f"  [yellow]{mod.name}[/]: {len(mf)} finding(s)")
            except Exception as exc:
                console.print(f"  [red]{mod.name} error: {exc}[/]")

        result.findings.extend(module_findings)
        result.findings = assign_scores(result.findings)
        result.modules_run = [m.name for m in mods] + (
            ["tenant_isolation"] if ctx_info.org_id else []
        )

        # ── Phase 6: Report ──────────────────────────────────────────
        console.print(Rule("[bold cyan]Phase 6 -- Report[/]"))
        reporter = Reporter(result)
        reporter.write(output, fmt)  # type: ignore[arg-type]
        console.print(f"  Report : [green]{output}[/]")

        enum_out = output.rsplit(".", 1)[0] + "_enum.json"
        enum_data = {
            "user_context": {
                "user_id": ctx_info.user_id,
                "email": ctx_info.email,
                "org_id": ctx_info.org_id,
                "role": ctx_info.role,
                "jwt_claims": ctx_info.raw_claims,
            },
            "accessible_queries": [
                {"field": r.field_name, "sensitive": bool(r.sensitive_matches),
                 "patterns": r.sensitive_matches, "preview": r.response_body[:400]}
                for r in enum_report.accessible_queries
            ],
            "sensitive_fields": [r.field_name for r in enum_report.sensitive_findings],
            "auth_blocked": enum_report.auth_blocked,
            "total_findings": len(result.findings),
        }
        Path(enum_out).write_text(_json.dumps(enum_data, indent=2), encoding="utf-8")
        console.print(f"  Enum   : [green]{enum_out}[/]")
        console.print(f"\n  Total findings: [bold]{len(result.findings)}[/]")


@cli.command()
@click.argument("url")
@click.option("-t", "--token",     required=True,  help="Bearer token (IdToken for Cognito/AppSync)")
@click.option("-H", "--header",    multiple=True,  help="Extra HTTP headers")
@click.option("-x", "--proxy",     default=None,   help="HTTP proxy")
@click.option("--timeout",         default=30,     type=int)
@click.option("--workers",         default=5,      type=int)
@click.option("--mutations",       is_flag=True,   help="Also enumerate mutations")
@click.option("--aggressive",      is_flag=True,   help="Enable DoS module")
@click.option("-o", "--output",    default="autopwn_report.html", help="Output report path")
@click.option("-f", "--format",    default="html", type=click.Choice(["html", "json", "markdown"]))
@click.option("-v", "--verbose",   is_flag=True)
def autopwn(
    url: str,
    token: str,
    header: tuple[str, ...],
    proxy: str | None,
    timeout: int,
    workers: int,
    mutations: bool,
    aggressive: bool,
    output: str,
    format: str,
    verbose: bool,
) -> None:
    """
    Fully autonomous pentest: decode token, discover org/user context,
    enumerate all accessible operations, test tenant isolation, run all
    vuln modules — no manual input needed beyond URL + token.
    """
    _print_banner()
    configure_logging(verbose)

    token = "".join(token.split())
    asyncio.run(_autopwn_pipeline(
        url, token, proxy, timeout, workers, mutations, aggressive, output, format,
        extra_headers=parse_headers(header),
    ))


# ---------------------------------------------------------------------------
# fullpwn command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("website_url")
@click.option("--email",        required=True,  help="Account email — OTP will be sent here")
@click.option("--auth-flow",    default="auto", type=click.Choice(["auto", "otp", "password"]),
              help="Auth flow: 'auto' tries OTP then password (default), 'otp' forces CUSTOM_AUTH, 'password' forces USER_PASSWORD_AUTH")
@click.option("--endpoint",     default=None,   help="Override AppSync GraphQL endpoint (skip scraping)")
@click.option("--pool-id",      default=None,   help="Override Cognito User Pool ID (skip scraping)")
@click.option("--client-id",    default=None,   help="Override Cognito Client ID (skip scraping)")
@click.option("-x", "--proxy",  default=None,   help="HTTP proxy")
@click.option("--timeout",      default=30,     type=int)
@click.option("--workers",      default=5,      type=int)
@click.option("--mutations",    is_flag=True,   help="Also enumerate mutations")
@click.option("--aggressive",   is_flag=True,   help="Enable DoS module")
@click.option("-o", "--output", default="fullpwn_report.html", help="Output report path")
@click.option("-f", "--format", default="html", type=click.Choice(["html", "json", "markdown"]))
@click.option("-v", "--verbose",is_flag=True)
def fullpwn(
    website_url: str,
    email: str,
    auth_flow: str,
    endpoint: str | None,
    pool_id: str | None,
    client_id: str | None,
    proxy: str | None,
    timeout: int,
    workers: int,
    mutations: bool,
    aggressive: bool,
    output: str,
    format: str,
    verbose: bool,
) -> None:
    """
    Zero-to-pwn from just a website URL and email.

    Scrapes JS bundles for AppSync endpoint + Cognito config, triggers OTP
    (or prompts for password), exchanges for IdToken, then runs full autopwn.
    """
    _print_banner()
    configure_logging(verbose)

    from rich.rule import Rule
    from gqlpwn.core.cognito_auth import (
        AuthResult,
        auto_auth,
        complete_otp_auth,
        initiate_otp_auth,
        password_auth,
        scrape_app_config,
    )

    # ── Step 1: Scrape JS bundles ────────────────────────────────────────
    console.print(Rule("[bold cyan]Step 1 -- Scraping JS bundles[/]"))
    with console.status(f"Fetching {website_url} and scanning JS bundles..."):
        try:
            app_cfg = scrape_app_config(
                website_url,
                timeout=timeout,
                endpoint_override=endpoint,
                pool_id_override=pool_id,
                client_id_override=client_id,
            )
        except Exception as exc:
            console.print(f"  [red]Scrape failed: {exc}[/]")
            raise SystemExit(1)

    console.print(f"  GraphQL endpoint : [cyan]{app_cfg.graphql_endpoint}[/]")
    console.print(f"  Cognito pool     : [dim]{app_cfg.user_pool_id}[/]")
    console.print(f"  Client ID        : [dim]{app_cfg.client_id}[/]")
    console.print(f"  Region           : [dim]{app_cfg.region}[/]")

    # ── Step 2: Authenticate ─────────────────────────────────────────────
    console.print(Rule("[bold cyan]Step 2 -- Cognito Authentication[/]"))
    id_token: str

    def _prompt(msg: str) -> str:
        hide = "password" in msg.lower() or "otp" not in msg.lower()
        return click.prompt(f"  {msg}", hide_input=hide)

    try:
        if auth_flow == "auto":
            console.print(f"  Probing auth flows for [bold]{email}[/]...")
            result = auto_auth(
                app_cfg.client_id, app_cfg.region, email, timeout, prompt_fn=_prompt
            )
            id_token = result.id_token
            console.print(f"  Flow used: [dim]{result.flow_used}[/]")
        elif auth_flow == "otp":
            console.print(f"  Triggering OTP to [bold]{email}[/]...")
            session = initiate_otp_auth(app_cfg.client_id, app_cfg.region, email, timeout)
            console.print("  OTP sent. Check your inbox.")
            otp = click.prompt("  Enter OTP")
            id_token = complete_otp_auth(
                app_cfg.client_id, app_cfg.region, email, session, otp, timeout
            )
        else:  # password
            password = click.prompt("  Password", hide_input=True)
            id_token = password_auth(
                app_cfg.client_id, app_cfg.region, email, password, timeout
            )
    except Exception as exc:
        console.print(f"  [red]Auth failed: {exc}[/]")
        raise SystemExit(1)

    console.print("  [green]Authenticated — IdToken acquired[/]")

    # ── Steps 3–8: Full autopwn pipeline ────────────────────────────────
    asyncio.run(_autopwn_pipeline(
        app_cfg.graphql_endpoint, id_token, proxy, timeout, workers,
        mutations, aggressive, output, format,
    ))


# ---------------------------------------------------------------------------
# enum command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("url")
@click.option("-H", "--header",    multiple=True,  help="HTTP header (repeatable)")
@click.option("-c", "--cookie",    default=None)
@click.option("-x", "--proxy",     default=None)
@click.option("-t", "--timeout",   default=30, type=int)
@click.option("--org-id",          default=None,   help="Your organization_id (for tenant isolation testing)")
@click.option("--mutations",       is_flag=True,   help="Also enumerate mutations (careful on prod)")
@click.option("--workers",         default=5, type=int)
@click.option("-o", "--output",    default=None,   help="Write JSON results to file")
@click.option("-v", "--verbose",   is_flag=True)
def enum(
    url: str,
    header: tuple[str, ...],
    cookie: str | None,
    proxy: str | None,
    timeout: int,
    org_id: str | None,
    mutations: bool,
    workers: int,
    output: str | None,
    verbose: bool,
) -> None:
    """
    Deep enumeration: fire every query/mutation, map what returns data,
    flag sensitive responses, and test tenant isolation via organization_id.
    """
    _print_banner()
    configure_logging(verbose)

    import json as _json
    from gqlpwn.core.enumerator import Enumerator
    from gqlpwn.core.introspector import Introspector
    from gqlpwn.core.parser import SchemaParser
    from gqlpwn.core.requester import Requester
    from gqlpwn.utils.models import ScanConfig

    config = ScanConfig(
        url=url,
        headers=parse_headers(header),
        cookies=parse_cookies(cookie),
        proxy=proxy,
        timeout=timeout,
        concurrency=workers,
    )

    async def _run() -> None:
        async with Requester(config) as req:
            # 1. Schema discovery
            with console.status("[bold cyan]Pulling schema...[/]"):
                intro = Introspector(req)
                intro_result = await intro.run()

            schema = SchemaParser().parse(intro_result.raw)
            console.print(
                f"Schema: [bold]{len(schema.queries)}[/] queries, "
                f"[bold]{len(schema.mutations)}[/] mutations, "
                f"[bold]{len(schema.types)}[/] types"
            )

            # 2. Enumerate
            enumerator = Enumerator(req, org_id=org_id, concurrency=workers)
            mut_list = schema.mutations if mutations else []

            with console.status(f"[bold cyan]Enumerating {len(schema.queries)} queries"
                                + (f" + {len(mut_list)} mutations" if mutations else "") + "...[/]"):
                report = await enumerator.run_all(schema.queries, mut_list, url)

            # 3. Print results
            _print_enum_report(report, mutations)

            # 4. Tenant isolation summary
            if org_id:
                console.print(f"\n[bold]Tenant isolation:[/] testing with org_id=[cyan]{org_id}[/]")
                from gqlpwn.modules.tenant_isolation import TenantIsolationModule
                from gqlpwn.utils.models import RunContext, ScanResult, ScanConfig as SC
                result = ScanResult(target=url)
                result.gql_schema = schema
                ctx_obj = RunContext(config=config, result=result, requester=req)
                mod = TenantIsolationModule(own_org_id=org_id)
                findings = await mod.run(ctx_obj)
                if findings:
                    console.print(f"\n[bold red]TENANT ISOLATION FAILURES: {len(findings)}[/]")
                    for f in findings:
                        console.print(f"  [red]{f.severity.upper()}[/] {f.title}")
                        console.print(f"  Evidence: {f.evidence[:200]}")
                else:
                    console.print("[green]No cross-tenant access confirmed[/]")

            # 5. Write output
            if output:
                data = {
                    "target": url,
                    "accessible_queries": [
                        {"field": r.field_name, "has_sensitive": bool(r.sensitive_matches),
                         "sensitive_patterns": r.sensitive_matches,
                         "response_preview": r.response_body[:300]}
                        for r in report.accessible_queries
                    ],
                    "accessible_mutations": [
                        {"field": r.field_name, "response_preview": r.response_body[:300]}
                        for r in report.accessible_mutations
                    ],
                    "sensitive_findings": [
                        {"field": r.field_name, "patterns": r.sensitive_matches,
                         "response_preview": r.response_body[:400]}
                        for r in report.sensitive_findings
                    ],
                    "auth_blocked": report.auth_blocked,
                }
                Path(output).write_text(_json.dumps(data, indent=2), encoding="utf-8")
                console.print(f"\n[green]Results written to {output}[/]")

    asyncio.run(_run())


def _print_enum_report(report: object, show_mutations: bool) -> None:
    from gqlpwn.core.enumerator import EnumReport
    r: EnumReport = report  # type: ignore

    console.print(f"\n[bold]Accessible queries ({len(r.accessible_queries)}/{r.total_queries}):[/]")
    for res in r.accessible_queries:
        flag = " [red][SENSITIVE][/]" if res.sensitive_matches else ""
        console.print(f"  [green]{res.field_name}[/]{flag}")

    if show_mutations and r.accessible_mutations:
        console.print(f"\n[bold]Accessible mutations ({len(r.accessible_mutations)}/{r.total_mutations}):[/]")
        for res in r.accessible_mutations:
            console.print(f"  [yellow]{res.field_name}[/]")

    if r.sensitive_findings:
        console.print(f"\n[bold red]Sensitive data in {len(r.sensitive_findings)} responses:[/]")
        for res in r.sensitive_findings:
            console.print(f"  [red]{res.field_name}[/] -- matched: {', '.join(res.sensitive_matches)}")
            console.print(f"    Preview: {res.response_body[:200]}")

    console.print(f"\n[dim]Auth-blocked: {len(r.auth_blocked)} | GQL errors: {len(r.gql_errors)}[/]")


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
