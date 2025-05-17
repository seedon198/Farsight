"""Entry point for the FARSIGHT CLI tool."""

import typer
from typing import Optional
import sys

from farsight import __version__

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
    """Run the FARSIGHT CLI."""
    try:
        # Import commands here to avoid circular imports
        from farsight.cli.scan import app as scan_app
        
        # Add subcommands
        app.add_typer(scan_app, name="scan")
        
        # Run the app
        app()
    except Exception as e:
        typer.secho(f"Error: {str(e)}", fg=typer.colors.RED)
        sys.exit(1)


if __name__ == "__main__":
    run()