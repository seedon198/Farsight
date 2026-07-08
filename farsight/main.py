"""Entry point for the FARSIGHT CLI tool.

This module provides the main CLI interface for FARSIGHT, handling command
registration and execution flow.
"""

import typer
import sys

from farsight import __version__

# Windows consoles default to a legacy codepage (e.g. cp1252) that can't
# encode the emoji/status glyphs used throughout the CLI and reports,
# crashing the whole scan on an UnicodeEncodeError. Force UTF-8 on stdio
# so output is consistent across platforms regardless of the host codepage.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(
    help="FARSIGHT - CLI-Based Recon and Threat Intelligence Framework",
    add_completion=True,
)


@app.callback()
def callback():
    """FARSIGHT CLI-Based Recon and Threat Intelligence Framework."""
    pass


@app.command()
def version():
    """Display the version of FARSIGHT."""
    typer.echo(f"FARSIGHT v{__version__}")


def run():
    """Run the FARSIGHT CLI.

    This function initializes the CLI application, registers commands,
    and handles the main execution flow with proper error handling.
    """
    try:
        # Import commands here to avoid circular imports
        from farsight.cli.scan import scan
        from farsight.cli.web import web

        # Add commands directly to the main app
        app.command()(scan)
        app.command()(web)

        # Run the main CLI application
        app()
    except Exception as e:
        typer.secho(f"Error: {str(e)}", fg=typer.colors.RED)
        sys.exit(1)


if __name__ == "__main__":
    run()
