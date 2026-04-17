"""GhostGuard CLI entry point.

Provides the ``ghostguard`` command, powered by Typer and Rich.

Commands:
  serve      Start the GhostGuard security proxy server
  evaluate   Evaluate a single tool call against the policy
  validate   Validate a policy YAML file
  audit      Query and display recent audit events
  init       Generate a starter policy.yaml
  version    Print the GhostGuard version
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ghostguard import __version__

app = typer.Typer(
    name="ghostguard",
    help="AI Agent Security Proxy — intercept, evaluate, and audit LLM tool calls.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

_STARTER_POLICY = """\
# GhostGuard Policy — Starter Template
# See https://github.com/joemunene-by/ghostguard for full docs.

name: default
version: "1.0"
description: Starter policy — sensible defaults for development

defaults:
  verdict: allow

rules:
  # Block destructive filesystem operations
  - tool: "rm"
    verdict: deny
    reason: "Deleting files is not permitted"

  - tool: "rm_rf"
    verdict: deny
    reason: "Recursive deletion is never allowed"

  # Sandbox network access
  - tool: "curl"
    verdict: sandbox
    reason: "Network requests require sandboxed execution"

  - tool: "http_request"
    verdict: sandbox
    reason: "HTTP requests are sandboxed"

  # Block shell execution
  - tool: "execute_command"
    verdict: deny
    reason: "Arbitrary command execution is blocked"

  # Allow code reading/writing
  - tool: "read_file"
    verdict: allow

  - tool: "write_file"
    verdict: allow
    reason: "File writing allowed in development mode"
"""


# ------------------------------------------------------------------
# serve
# ------------------------------------------------------------------


@app.command()
def serve(
    policy: str = typer.Option(
        "policy.yaml",
        "--policy",
        "-p",
        help="Path to the YAML policy file.",
    ),
    port: int = typer.Option(8000, "--port", help="Port to listen on."),
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address."),
    upstream: str = typer.Option(
        "https://api.openai.com",
        "--upstream",
        "-u",
        help="Upstream LLM API base URL.",
    ),
    db_path: str = typer.Option(
        "ghostguard.db",
        "--db",
        help="Path to the audit SQLite database.",
    ),
    dashboard: bool = typer.Option(
        True, "--dashboard/--no-dashboard", help="Enable web dashboard."
    ),
    reload: bool = typer.Option(
        False, "--reload", help="Enable auto-reload (dev mode)."
    ),
) -> None:
    """Start the GhostGuard security proxy server."""
    import os

    import uvicorn

    console.print(
        Panel.fit(
            f"[bold green]GhostGuard[/bold green] v{__version__} starting...\n"
            f"  Policy:    {policy}\n"
            f"  Upstream:  {upstream}\n"
            f"  Listen:    {host}:{port}\n"
            f"  Dashboard: {'enabled' if dashboard else 'disabled'}",
            title="GhostGuard",
            border_style="green",
        )
    )

    # Communicate settings to the app factory via environment variables
    os.environ["GHOSTGUARD_POLICY_PATH"] = policy
    os.environ["GHOSTGUARD_UPSTREAM_URL"] = upstream
    os.environ["GHOSTGUARD_DB_PATH"] = db_path
    os.environ["GHOSTGUARD_DASHBOARD_ENABLED"] = str(dashboard).lower()

    uvicorn.run(
        "ghostguard.proxy.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ------------------------------------------------------------------
# evaluate (from the policy agent's original CLI)
# ------------------------------------------------------------------


@app.command()
def evaluate(
    tool_name: str = typer.Argument(..., help="Name of the tool to evaluate."),
    arguments: str = typer.Argument("{}", help="JSON string of tool arguments."),
    policy: str = typer.Option(
        "policy.yaml", "--policy", "-p", help="Path to the YAML policy file."
    ),
    session_id: str = typer.Option(
        "cli", "--session", "-s", help="Session identifier."
    ),
) -> None:
    """Evaluate a single tool call against the policy and print the decision."""
    from ghostguard._types import Verdict

    try:
        args = json.loads(arguments)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid JSON arguments:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    path = Path(policy)
    if not path.is_file():
        console.print(f"[red]Policy file not found:[/red] {path}")
        raise typer.Exit(code=1)

    try:
        from ghostguard.policy.engine import PolicyEngine

        engine = PolicyEngine.from_yaml(path)
        decision = engine.evaluate(
            tool_name=tool_name, arguments=args, session_id=session_id
        )
    except ImportError:
        console.print("[red]PolicyEngine not available. Install the policy module first.[/red]")
        raise typer.Exit(code=1)

    colour = {
        Verdict.ALLOW: "green",
        Verdict.DENY: "red",
        Verdict.SANDBOX: "yellow",
        Verdict.PENDING: "blue",
    }.get(decision.verdict, "white")

    table = Table(title="GhostGuard Decision", show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Tool", tool_name)
    table.add_row("Verdict", f"[{colour}]{decision.verdict.value}[/{colour}]")
    table.add_row("Reason", decision.reason)
    table.add_row("Tier", decision.tier)
    table.add_row("Latency", f"{decision.latency_ms:.2f} ms")
    console.print(table)

    if decision.verdict == Verdict.DENY:
        raise typer.Exit(code=2)


# ------------------------------------------------------------------
# validate
# ------------------------------------------------------------------


@app.command()
def validate(
    policy_path: str = typer.Argument(
        "policy.yaml", help="Path to the policy YAML file."
    ),
) -> None:
    """Validate a policy YAML file and print a summary."""
    import yaml

    path = Path(policy_path)
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {policy_path}")
        raise typer.Exit(code=1)

    try:
        with path.open() as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:
        console.print(f"[red]YAML parse error:[/red] {exc}")
        raise typer.Exit(code=1)

    if not isinstance(data, dict):
        console.print("[red]Error:[/red] Policy file must be a YAML mapping")
        raise typer.Exit(code=1)

    # Try loading via the real policy engine if available
    try:
        from ghostguard.policy.engine import PolicyEngine
        from ghostguard.policy.loader import load_policy

        cfg = load_policy(path)
        console.print(
            f"[green]Policy loaded successfully.[/green]  "
            f"{len(cfg.tools)} tool rules, {len(cfg.patterns)} patterns."
        )
    except ImportError:
        console.print(
            "[yellow]PolicyEngine not available; validating YAML structure only[/yellow]"
        )
    except Exception as exc:
        console.print(f"[red]Policy engine error:[/red] {exc}")
        raise typer.Exit(code=1)

    # Print summary
    rules = data.get("rules", [])
    defaults = data.get("defaults", {})
    name = data.get("name", "unnamed")

    summary_table = Table(title=f"Policy: {name}")
    summary_table.add_column("Field", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Name", str(name))
    summary_table.add_row("Version", str(data.get("version", "unknown")))
    summary_table.add_row("Description", str(data.get("description", "")))
    summary_table.add_row("Default verdict", str(defaults.get("verdict", "not set")))
    summary_table.add_row("Number of rules", str(len(rules)))

    console.print(summary_table)

    if rules:
        rules_table = Table(title="Rules")
        rules_table.add_column("#", style="dim")
        rules_table.add_column("Tool", style="cyan")
        rules_table.add_column("Verdict", style="bold")
        rules_table.add_column("Reason")

        for i, rule in enumerate(rules, 1):
            verdict_val = str(rule.get("verdict", ""))
            verdict_display = {
                "allow": "[green]allow[/green]",
                "deny": "[red]deny[/red]",
                "sandbox": "[yellow]sandbox[/yellow]",
            }.get(verdict_val, verdict_val)
            rules_table.add_row(
                str(i),
                str(rule.get("tool", "*")),
                verdict_display,
                str(rule.get("reason", "")),
            )

        console.print(rules_table)

    console.print("\n[green]Validation passed.[/green]")


# ------------------------------------------------------------------
# audit
# ------------------------------------------------------------------


@app.command()
def audit(
    last: int = typer.Option(
        20, "--last", "-n", help="Number of recent events to show."
    ),
    tool: Optional[str] = typer.Option(
        None, "--tool", "-t", help="Filter by tool name."
    ),
    verdict: Optional[str] = typer.Option(
        None, "--verdict", "-v", help="Filter by verdict."
    ),
    db_path: str = typer.Option(
        "ghostguard.db", "--db", help="Path to audit database."
    ),
    export_path: Optional[str] = typer.Option(
        None, "--export", help="Export to file (JSONL or CSV)."
    ),
) -> None:
    """Query and display recent audit events."""

    async def _query() -> None:
        from ghostguard.audit.store import AuditStore

        store = AuditStore(db_path)
        try:
            await store.initialize()
            events = await store.query(
                limit=last,
                tool_name=tool,
                verdict=verdict,
            )
        finally:
            await store.close()

        if not events:
            console.print("[dim]No audit events found.[/dim]")
            return

        # Export if requested
        if export_path:
            from ghostguard.audit.export import export_csv, export_jsonl

            p = Path(export_path)
            if p.suffix == ".csv":
                count = export_csv(events, p)
            else:
                count = export_jsonl(events, p)
            console.print(f"[green]Exported {count} events to {p}[/green]")
            return

        # Display table
        table = Table(title=f"Audit Events (last {last})")
        table.add_column("Time", style="dim", width=20)
        table.add_column("Tool", style="cyan")
        table.add_column("Verdict", width=8)
        table.add_column("Tier", style="dim", width=8)
        table.add_column("Reason", max_width=40)
        table.add_column("Latency", justify="right", width=8)

        for ev in events:
            verdict_display = {
                "allow": "[green]ALLOW[/green]",
                "deny": "[red]DENY[/red]",
                "sandbox": "[yellow]SANDBOX[/yellow]",
            }.get(ev.verdict, ev.verdict)

            # Shorten timestamp for display
            ts = ev.timestamp
            if "T" in ts:
                ts = ts.split("T")[1][:8]

            table.add_row(
                ts,
                ev.tool_name,
                verdict_display,
                ev.tier,
                ev.reason[:40] if ev.reason else "",
                f"{ev.latency_ms:.1f}ms",
            )

        console.print(table)

    asyncio.run(_query())


# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------


@app.command()
def init(
    output: str = typer.Option(
        "policy.yaml", "--output", "-o", help="Output file path."
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing file."
    ),
) -> None:
    """Generate a starter policy.yaml in the current directory."""
    path = Path(output)
    if path.exists() and not force:
        console.print(
            f"[yellow]File already exists:[/yellow] {path}\n"
            "Use --force to overwrite."
        )
        raise typer.Exit(code=1)

    path.write_text(_STARTER_POLICY)
    console.print(f"[green]Created starter policy at[/green] {path}")
    console.print("Edit the file to customise rules for your use case.")


# ------------------------------------------------------------------
# version
# ------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the GhostGuard version."""
    console.print(f"ghostguard {__version__}")


if __name__ == "__main__":
    app()
