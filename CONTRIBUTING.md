# Contributing to FARSIGHT

Thanks for considering a contribution. FARSIGHT is a recon and threat-intelligence CLI (with an optional web UI) — contributions of all sizes are welcome, from typo fixes to new modules.

## Getting set up

```bash
git clone https://github.com/seedon198/Farsight.git
cd Farsight
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
```

Requires Python 3.10+. If you're working on the web UI (`farsight/web/`), also install:

```bash
pip install -r requirements-web.txt
```

Poetry is also supported (`pyproject.toml` is the source of truth for dependencies):

```bash
poetry install --with dev,web
```

## Before opening a PR

```bash
black farsight/ tests/
flake8 farsight/ tests/
pytest tests/ -v
```

CI runs `black --check`, `flake8`, and the full test suite on `ubuntu-latest` and `windows-latest`, Python 3.10 and 3.12 — please make sure all of that passes locally first. If you have `pre-commit` installed, `pre-commit install` will run the formatting/lint checks automatically on commit.

## Making changes

- **Branch from `dev`**, not `main`. Open PRs against `dev`.
- Keep PRs focused — one fix or feature per PR is easier to review than a bundle of unrelated changes.
- Add or update tests for behavior you change. See `tests/` for the existing patterns (pytest + pytest-asyncio, `unittest.mock.AsyncMock` for the async modules).
- If you're touching `farsight/cli/scan.py` or `farsight/modules/report_writer.py`, run a real scan (`python -m farsight scan example.com --all --verbose`) before and after — those are the demo-critical path.
- If you're touching the web UI (`farsight/web/`), run `python -m farsight web` and click through the change in a browser; the WebSocket event contract in `farsight/web/events.py` is shared by the live scan orchestrator and the offline replay engine, so changes there affect both.

## Reporting bugs

Open a GitHub issue with steps to reproduce, your OS/Python version, and the exact command you ran. For **security vulnerabilities**, do not open a public issue — see [SECURITY.md](.github/SECURITY.md) instead.

## Code style

- Formatted with [black](https://github.com/psf/black), linted with `flake8`, imports sorted with `isort`.
- Type hints are used throughout the module return shapes; please keep new code consistent with that.
- Prefer small, readable functions over cleverness — this is a security tool, and reviewers (including future-you) need to be able to trust what it's doing.

## License

By contributing, you agree your contributions will be licensed under the project's [MIT License](LICENSE).
