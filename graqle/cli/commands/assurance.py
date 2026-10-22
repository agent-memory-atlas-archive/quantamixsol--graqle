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

import typer

from graqle.assurance.settings import ENV_FLAG, is_dag_enabled
from graqle.cli.console import create_console
from graqle.config.exceptions import ConfigurationError

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
