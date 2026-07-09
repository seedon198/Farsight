# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Local-first web UI (`python -m farsight web`): live WebSocket-driven scan progress, stat tiles, attack-surface graph, typosquat risk panel, and an in-browser report with Markdown/PDF download. No authentication — binds to `127.0.0.1` by default.
- Offline replay/demo mode (`farsight web --demo`) that replays a pre-captured scan fixture with zero network calls — a safety net for presenting on unreliable networks. Capture your own fixture with `scripts/capture_demo_fixture.py`.
- Windows added to the CI test matrix (previously `ubuntu-latest` only).
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates, `.env.example`, `.pre-commit-config.yaml`.

### Fixed
- Crash on Windows: `python -m farsight scan --verbose` (and any encode error during report generation) raised an uncaught `UnicodeEncodeError` on non-UTF-8 consoles (the Windows default), sometimes after a full successful scan, leaving a 0-byte report. Console I/O and report file I/O now force UTF-8.
- Generated reports could contradict themselves: the executive summary and the detailed Email Security section read two different, unsynchronized data shapes for SPF/DMARC status. Both now read the same data.
- NS records always rendered as `N/A` in reports (renderer had no case for the `NS` record type).
- Duplicate `### DNS Records` heading in generated reports.
- Raw ANSI color codes leaking into piped/non-terminal output instead of only coloring real terminals.

## [0.1.0] - 2025-05-17

Initial release: organization discovery (WHOIS, certificate transparency, passive DNS), reconnaissance (DNS enumeration, subdomain discovery, port scanning), threat intelligence (leak/credential/dark-web checks), typosquatting detection, news monitoring, and Markdown/PDF report generation. API-optional throughout.
