"""`farsight web` — launch the local web UI."""

import webbrowser
from pathlib import Path
from typing import Optional

import typer
import uvicorn

from farsight.web.app import DEFAULT_FIXTURE, create_app


def web(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host to bind (loopback only; this UI has no authentication)",
    ),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind"),
    open_browser: bool = typer.Option(
        True,
        "--open-browser/--no-browser",
        help="Open the UI in a browser automatically",
    ),
    demo: bool = typer.Option(
        False,
        "--demo",
        help="Offline demo mode: replay a pre-captured scan instead of "
        "hitting the network. Use when the venue network can't be "
        "trusted for a live scan.",
    ),
    fixture: Optional[Path] = typer.Option(
        None,
        "--fixture",
        help="Path to a captured demo fixture (default: the bundled "
        "example.com fixture). See scripts/capture_demo_fixture.py "
        "to record your own.",
    ),
):
    """
    Launch the local FARSIGHT web UI.

    Runs a local-only web server (no authentication) that wraps the
    scan modules with a live-progress browser UI. Intended for demo
    use on the presenter's own machine.
    """
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.secho(
            "Warning: FARSIGHT's web UI has no authentication. "
            "Binding to a non-loopback host exposes it to your network.",
            fg=typer.colors.YELLOW,
        )

    demo_fixture: Optional[Path] = None
    if demo:
        demo_fixture = fixture or DEFAULT_FIXTURE
        if not demo_fixture.exists():
            typer.secho(f"Demo fixture not found: {demo_fixture}", fg=typer.colors.RED)
            typer.secho(
                "Capture one with: python scripts/capture_demo_fixture.py <domain>",
                fg=typer.colors.YELLOW,
            )
            raise typer.Exit(1)
        typer.secho(
            f"Demo mode: replaying {demo_fixture.name} — no network calls will be made.",
            fg=typer.colors.BRIGHT_CYAN,
        )

    url = f"http://{host}:{port}"
    typer.secho(f"Starting FARSIGHT web UI at {url}", fg=typer.colors.BRIGHT_GREEN)

    if open_browser:
        webbrowser.open(url)

    uvicorn.run(
        create_app(demo_fixture=demo_fixture), host=host, port=port, log_level="info"
    )
