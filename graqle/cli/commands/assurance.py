"""graq assurance -- DAG-2026 assurance studies (flag-guarded, read-only on the dataset).

`graq assurance threshold-study --dataset <rows.jsonl> --out <dir>` runs the E2
baseline arms and writes ``e2-report-<run_id>.json`` and ``.runlog`` into <dir>.

Exit codes:
    0  Report written.
    2  The dataset is unreadable or malformed, the run id is invalid, or the
       confidence-vector configuration is invalid.
    3  ``GRAQLE_DAG_ENABLED`` is not set -- the command is flag-gated off.
"""

# -- graqle:intelligence --
# module: graqle.cli.commands.assurance
# risk: LOW (impact radius: 1 module -- registered in cli/main.py only)
# dependencies: typer, graqle.assurance.{threshold_study,cv_settings,settings}, graqle.cli.console
# constraints: writes only the two report files; never writes to a graph
# -- /graqle:intelligence --

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from graqle.assurance.settings import ENV_FLAG, is_dag_enabled
from graqle.cli.console import create_console
from graqle.config.exceptions import ConfigurationError

if TYPE_CHECKING:  # annotation only: keeps the escalation modules out of the flag-off import graph
    from graqle.assurance.escalation import JsonlEscalationQueue

console = create_console()

assurance_app = typer.Typer(
    name="assurance",
    help="DAG-2026 assurance studies (flag-guarded).",
)


@assurance_app.callback()
def _assurance_callback() -> None:
    """DAG-2026 assurance studies (flag-guarded).

    A no-op callback so the single subcommand keeps its name (see ``dag.py``).
    """


@assurance_app.command("threshold-study")
def threshold_study_command(
    dataset: Path = typer.Option(
        ...,
        "--dataset",
        exists=True,
        dir_okay=False,
        help="Labelled rows, one JSON object per line.",
    ),
    out: Path = typer.Option(..., "--out", file_okay=False, help="Directory for the report files."),
    run_id: str = typer.Option(
        "", "--run-id", help="Report id; defaults to a prefix of the dataset hash."
    ),
) -> None:
    """Run the E2 baseline arms over a labelled dataset and write the report."""
    if not is_dag_enabled():
        console.print(
            f"[bold red]{ENV_FLAG} is not set[/bold red] -- "
            "`graq assurance threshold-study` is flag-gated off."
        )
        raise typer.Exit(3)

    # Lazy: the confidence-vector modules stay out of the flag-off import graph (AC-22).
    from graqle.assurance.cv_settings import load_confidence_vector_settings
    from graqle.assurance.threshold_study import DatasetError, run_threshold_study

    if not run_id:
        run_id = "run-" + hashlib.sha256(dataset.read_bytes()).hexdigest()[:12]
    try:
        settings = load_confidence_vector_settings()
        report_path = run_threshold_study(dataset, out, settings, run_id)
    except ConfigurationError as exc:
        console.print(f"[bold red]Invalid confidence-vector configuration:[/bold red] {exc}")
        raise typer.Exit(2) from None
    except (DatasetError, ValueError) as exc:
        console.print(f"[bold red]Threshold study refused:[/bold red] {exc}")
        raise typer.Exit(2) from None

    console.print(f"[green]Report written:[/green] {report_path}")
    raise typer.Exit(0)


@assurance_app.command("intervention-study")
def intervention_study_command(
    tasks: Path = typer.Option(
        ...,
        "--tasks",
        exists=True,
        dir_okay=False,
        help="Synthetic tasks, one JSON object per line.",
    ),
    params: Path = typer.Option(
        ...,
        "--params",
        exists=True,
        dir_okay=False,
        help="Study parameters as a JSON object (every field required).",
    ),
    out: Path = typer.Option(..., "--out", file_okay=False, help="Directory for the report files."),
    run_id: str = typer.Option("", "--run-id", help="Run id (default: derived from the tasks)."),
) -> None:
    """Run the E7 intervention study and write the report.

    Uses the merged REPLAN controller when it is importable; otherwise a stub, and the
    report is then labelled as a dev/practice run (never an E7 result).
    """
    if not is_dag_enabled():
        console.print(
            f"[bold red]{ENV_FLAG} is not set[/bold red] -- "
            "`graq assurance intervention-study` is flag-gated off."
        )
        raise typer.Exit(3)

    import json

    from pydantic import ValidationError

    from graqle.assurance.intervention_study import (
        DatasetError,
        StubReplanController,
        StudyParams,
        run_intervention_study,
    )

    try:
        from graqle.assurance import replan as replan_module

        factory: Any = replan_module.ReplanController
    except (ImportError, AttributeError):
        factory = StubReplanController
        console.print("[yellow]Real ReplanController missing: stub run, NOT an E7 result.[/yellow]")

    if not run_id:
        run_id = "run-" + hashlib.sha256(tasks.read_bytes()).hexdigest()[:12]
    try:
        study_params = StudyParams.model_validate(json.loads(params.read_text(encoding="utf-8")))
        report_path = run_intervention_study(tasks, out, study_params, run_id, factory)
    except (OSError, json.JSONDecodeError, ValidationError, DatasetError, ValueError) as exc:
        console.print(f"[bold red]Intervention study refused:[/bold red] {exc}")
        raise typer.Exit(2) from None

    console.print(f"[green]Report written:[/green] {report_path}")
    raise typer.Exit(0)


escalations_app = typer.Typer(
    name="escalations",
    help="Review packages escalated by the DAG gate (flag-guarded).",
)
assurance_app.add_typer(escalations_app, name="escalations")


def _open_escalation_queue() -> JsonlEscalationQueue:
    """Return the configured escalation queue, or exit non-zero (fail closed).

    Only the file-backed queue is reachable from a separate process; ``memory`` and
    ``custom`` queues live inside the host application, so they are refused here.
    """
    if not is_dag_enabled():
        console.print(
            f"[bold red]{ENV_FLAG} is not set[/bold red] -- "
            "`graq assurance escalations` is flag-gated off."
        )
        raise typer.Exit(3)

    # Lazy: the escalation modules stay out of the flag-off import graph.
    from graqle.assurance.escalation import JsonlEscalationQueue
    from graqle.assurance.escalation_settings import EscalationSettings

    try:
        settings = EscalationSettings.from_env()
    except ConfigurationError as exc:
        console.print(f"[bold red]Invalid escalation configuration:[/bold red] {exc}")
        raise typer.Exit(2) from None
    if settings.queue != "jsonl":
        console.print(
            f"[bold red]Escalation queue {settings.queue!r} is not reachable from the CLI;[/bold red] "
            "only the 'jsonl' queue is supported."
        )
        raise typer.Exit(2)
    return JsonlEscalationQueue(settings.queue_path)


@escalations_app.callback()
def _escalations_callback() -> None:
    """Review packages escalated by the DAG gate (flag-guarded)."""


@escalations_app.command("list")
def escalations_list_command(
    role: str = typer.Option("", "--role", help="Only packages routed to this role."),
) -> None:
    """List open and acknowledged review packages."""
    queue = _open_escalation_queue()
    try:
        packages = queue.list_open(role or None)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Escalation queue unreadable:[/bold red] {type(exc).__name__}")
        raise typer.Exit(2) from None
    for pkg in packages:
        console.print(
            f"{pkg.package_id}  {pkg.status}  tier={pkg.impact_tier.value}  "
            f"role={pkg.route_to_role}  requested={pkg.requested_decision}"
        )
    raise typer.Exit(0)


@escalations_app.command("ack")
def escalations_ack_command(
    package_id: str = typer.Argument(..., help="Review package id."),
    actor: str = typer.Option(..., "--actor", help="Acknowledging actor id (must be eligible)."),
) -> None:
    """Acknowledge an open review package."""
    queue = _open_escalation_queue()
    try:
        done = queue.ack(package_id, actor)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Escalation queue failed:[/bold red] {type(exc).__name__}")
        raise typer.Exit(2) from None
    if not done:
        console.print("[bold red]Acknowledge refused:[/bold red] unknown, closed or ineligible.")
        raise typer.Exit(1)
    console.print(f"[green]Acknowledged:[/green] {package_id}")
    raise typer.Exit(0)


@escalations_app.command("resolve")
def escalations_resolve_command(
    package_id: str = typer.Argument(..., help="Review package id."),
    actor: str = typer.Option(..., "--actor", help="Resolving actor id (must be eligible)."),
    decision: str = typer.Option(
        ..., "--decision", help="approve_execute | approve_replan | reject | defer."
    ),
    justification: str = typer.Option(..., "--justification", help="Why (required, non-empty)."),
) -> None:
    """Resolve a review package with a decision and a justification."""
    queue = _open_escalation_queue()
    try:
        done = queue.resolve(package_id, actor, decision, justification)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Escalation queue failed:[/bold red] {type(exc).__name__}")
        raise typer.Exit(2) from None
    if not done:
        console.print(
            "[bold red]Resolve refused:[/bold red] unknown or closed package, "
            "ineligible actor, invalid decision or empty justification."
        )
        raise typer.Exit(1)
    console.print(f"[green]Resolved:[/green] {package_id}")
    raise typer.Exit(0)
