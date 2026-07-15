# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.0.0-beta.1] - 2026-07-16

### Added
- Local-first web UI (`python -m farsight web`): live WebSocket-driven scan progress, stat tiles, attack-surface graph, typosquat risk panel, and an in-browser report with Markdown/PDF download. No authentication — binds to `127.0.0.1` by default.
- Offline replay/demo mode (`farsight web --demo`) that replays a pre-captured scan fixture with zero network calls — a safety net for presenting on unreliable networks. Capture your own fixture with `scripts/capture_demo_fixture.py`.
- `masscan`-backed bulk port discovery (`MasscanScanner`) with an asyncio fallback, wired into `Recon.scan()`, with bounded outer concurrency to prevent fan-out exhaustion.
- IntelX Phonebook check added to the threat intelligence module, with local caching of IntelX search results to avoid spending duplicate credits on repeat lookups.
- Full IntelX/threat-intel details and Phonebook results surfaced in the web dashboard.
- Screenshot capture module for discovered domains, with graceful fallback when Playwright isn't installed.
- Windows added to the CI test matrix (previously `ubuntu-latest` only); pytest suite wired into CI.
- CI security gates: Gitleaks secret scanning, `pip-audit`, and CodeQL on every PR; linting/formatting switched to Ruff.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates, `.env.example`, `.pre-commit-config.yaml`.

### Changed
- Subdomain enumeration reworked: certificate transparency, brute force, permutation, scraping, and API-based techniques, with depth-scaled result caps and early termination once enough results are found.
- Port scanning now runs against every discovered subdomain, not just the primary domain; domain-vs-subdomain classification fixed so related domains aren't misclassified as subdomains.
- CLI output switched from box-drawn tables to a minimalist, borderless table format; emojis removed for more professional/scriptable output.

### Fixed
- Crash on Windows: `python -m farsight scan --verbose` (and any encode error during report generation) raised an uncaught `UnicodeEncodeError` on non-UTF-8 consoles (the Windows default), sometimes after a full successful scan, leaving a 0-byte report. Console I/O and report file I/O now force UTF-8.
- Generated reports could contradict themselves: the executive summary and the detailed Email Security section read two different, unsynchronized data shapes for SPF/DMARC status. Both now read the same data.
- NS records always rendered as `N/A` in reports (renderer had no case for the `NS` record type).
- Duplicate `### DNS Records` heading in generated reports.
- Raw ANSI color codes leaking into piped/non-terminal output instead of only coloring real terminals.
- IntelX API endpoint corrected for free-tier keys; fixed a result date-parsing crash and an incorrect `await` on synchronous IntelX result processing.
- `dnstwist` integration fixed to use the current `Fuzzer` API, restoring typosquat detection.
- Report writer crash when WHOIS data contained raw `datetime` objects.
- Critical `typer`/`click` incompatibility that broke the CLI; `click` pinned to `<8.3`.

### Security
- Patched 36 Dependabot advisories; bumped `dnspython` to `>=2.6.1` to fix the TuDoor DoS CVE; dropped EOL Python 3.9 support.

## [0.1.0] - 2025-05-17

Initial release: organization discovery (WHOIS, certificate transparency, passive DNS), reconnaissance (DNS enumeration, subdomain discovery, port scanning), threat intelligence (leak/credential/dark-web checks), typosquatting detection, news monitoring, and Markdown/PDF report generation. API-optional throughout.
