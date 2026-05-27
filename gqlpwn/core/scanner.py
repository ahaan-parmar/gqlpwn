"""Top-level scan orchestrator — wires together all components."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from gqlpwn.core.introspector import Introspector
from gqlpwn.core.parser import SchemaParser
from gqlpwn.core.requester import Requester
from gqlpwn.core.scorer import assign_scores
from gqlpwn.modules.base import BaseModule
from gqlpwn.utils.logger import get_logger
from gqlpwn.utils.models import RunContext, ScanConfig, ScanResult

logger = get_logger(__name__)
console = Console()

# Registry of all available modules (import lazily to avoid circular deps at load time)
MODULE_REGISTRY: dict[str, str] = {
    "info_disclosure": "gqlpwn.modules.info_disclosure.InfoDisclosureModule",
    "injection":       "gqlpwn.modules.injection.InjectionModule",
    "bola":            "gqlpwn.modules.bola.BolaModule",
    "auth":            "gqlpwn.modules.auth.AuthModule",
    "dos":             "gqlpwn.modules.dos.DosModule",
    "ssrf":            "gqlpwn.modules.ssrf.SsrfModule",
}


def _import_module_class(dotted: str) -> type[BaseModule]:
    module_path, cls_name = dotted.rsplit(".", 1)
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, cls_name)  # type: ignore[no-any-return]


def _resolve_modules(names: list[str], aggressive: bool) -> list[BaseModule]:
    selected = names or list(MODULE_REGISTRY.keys())
    instances: list[BaseModule] = []

    for name in selected:
        if name not in MODULE_REGISTRY:
            logger.warning("unknown_module", name=name)
            continue
        cls = _import_module_class(MODULE_REGISTRY[name])
        instance = cls()
        if instance.metadata.requires_aggressive and not aggressive:
            logger.warning(
                "module_skipped_requires_aggressive",
                module=name,
                hint="pass --aggressive to enable",
            )
            continue
        instances.append(instance)

    return instances


class Scanner:
    """
    Orchestrates a full vulnerability scan:

    1. Introspect the target schema (with fallback strategies)
    2. Parse the schema into structured models
    3. Run selected vulnerability modules concurrently
    4. Score findings
    5. Return a ScanResult ready for reporting
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def run(self) -> ScanResult:
        result = ScanResult(target=self.config.url)

        async with Requester(self.config) as requester:
            ctx = RunContext(config=self.config, result=result, requester=requester)

            # Phase 1 — schema discovery
            with console.status("[bold cyan]Discovering schema…[/]"):
                introspector = Introspector(
                    requester, wordlist_path=self.config.wordlist
                )
                intro_result = await introspector.run()

            parser = SchemaParser()
            result.gql_schema = parser.parse(intro_result.raw)
            result.introspection_enabled = intro_result.enabled

            if intro_result.method == "none":
                console.print("[yellow]⚠ Schema discovery failed — limited testing possible[/]")
            else:
                console.print(
                    f"[green]✓ Schema via [bold]{intro_result.method}[/bold]"
                    f" — {len(result.gql_schema.queries)} queries, "
                    f"{len(result.gql_schema.mutations)} mutations[/]"
                )

            # Phase 2 — module execution
            modules = _resolve_modules(self.config.modules, self.config.aggressive)
            if not modules:
                logger.error("no_modules_selected")
                return result

            all_findings = await self._run_modules(modules, ctx)
            result.findings = assign_scores(all_findings)
            result.modules_run = [m.name for m in modules]
            result.finished_at = datetime.utcnow()

        self._print_summary(result)
        return result

    async def _run_modules(
        self,
        modules: list[BaseModule],
        ctx: RunContext,
    ) -> list[Any]:
        findings = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running modules…", total=len(modules))

            async def _run_one(module: BaseModule) -> list[Any]:
                try:
                    logger.debug("module_start", module=module.name)
                    result = await module.run(ctx)
                    logger.debug("module_done", module=module.name, findings=len(result))
                    return result
                except Exception as exc:  # noqa: BLE001
                    logger.error("module_error", module=module.name, error=str(exc))
                    return []
                finally:
                    progress.advance(task)

            # Run modules with bounded concurrency (respect the semaphore in Requester)
            tasks = [_run_one(m) for m in modules]
            results = await asyncio.gather(*tasks)
            for batch in results:
                findings.extend(batch)

        return findings

    def _print_summary(self, result: ScanResult) -> None:
        by_sev = result.findings_by_severity()

        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        colors = {
            "critical": "red",
            "high": "bright_red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        for sev, color in colors.items():
            count = len(by_sev[sev])
            if count:
                table.add_row(f"[{color}]{sev.upper()}[/]", str(count))

        console.print(table)

        elapsed = (
            (result.finished_at - result.started_at).total_seconds()
            if result.finished_at
            else 0
        )
        console.print(
            f"\n[dim]Scanned [bold]{result.target}[/] in {elapsed:.1f}s | "
            f"{len(result.findings)} total findings[/]"
        )
