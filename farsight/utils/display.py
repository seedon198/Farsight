"""Minimalist CLI display helpers.

Renders scan summaries as clean, borderless key/value and column output
instead of hand-drawn box tables.
"""

from typing import Any, List, Optional, Sequence, Tuple

import typer

LABEL_COLOR = typer.colors.BRIGHT_BLACK
HEADER_COLOR = typer.colors.BRIGHT_BLACK


def section(title: str) -> None:
    """Print a section header."""
    typer.secho(f"\n{title}", fg=typer.colors.BRIGHT_CYAN)


def kv_rows(rows: Sequence[Tuple[str, Any, Optional[str]]]) -> None:
    """Print aligned "label  value" rows with no borders.

    Each row is (label, value, color). color may be None for the default.
    """
    if not rows:
        return
    width = max(len(label) for label, _, _ in rows)
    for label, value, color in rows:
        typer.secho(f"  {label:<{width}}  ", fg=LABEL_COLOR, nl=False)
        typer.secho(f"{value}", fg=color or typer.colors.WHITE)


def columns(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    row_colors: Optional[Sequence[Optional[str]]] = None,
) -> None:
    """Print a minimalist column table: header + underline, no vertical borders."""
    if not rows:
        return
    widths = [
        max(len(str(headers[i])), *(len(str(row[i])) for row in rows))
        for i in range(len(headers))
    ]
    def render(values: Sequence[Any]) -> str:
        cells = [f"{str(v):<{w}}" for v, w in zip(values, widths)]
        cells[-1] = str(values[-1])  # don't pad the last column
        return "  ".join(cells)

    header_line = render(headers)
    typer.secho(f"  {header_line}", fg=HEADER_COLOR, bold=True)
    typer.secho(f"  {'-' * len(header_line)}", fg=HEADER_COLOR)
    for i, row in enumerate(rows):
        color = row_colors[i] if row_colors else typer.colors.WHITE
        typer.secho(f"  {render(row)}", fg=color or typer.colors.WHITE)


def item_list(items: List[str], color: Optional[str] = None) -> None:
    """Print a plain indented list of items."""
    for item in items:
        typer.secho(f"  {item}", fg=color or typer.colors.WHITE)


def more(count: int, label: str) -> None:
    """Print a trailing "... and N more <label>" line."""
    typer.secho(f"  ... and {count} more {label}", fg=typer.colors.BRIGHT_BLACK)
