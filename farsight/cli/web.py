"""`farsight web` — launch the local web UI."""

import webbrowser

import typer
import uvicorn

from farsight.web.app import create_app


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

    url = f"http://{host}:{port}"
    typer.secho(f"Starting FARSIGHT web UI at {url}", fg=typer.colors.BRIGHT_GREEN)

    if open_browser:
        webbrowser.open(url)

    uvicorn.run(create_app(), host=host, port=port, log_level="info")
