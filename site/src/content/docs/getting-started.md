---
title: Getting Started
description: Install Farsight and run your first scan.
section: Start Here
order: 1
---

Farsight is a modular CLI recon and threat-intelligence framework. It maps a target's organization, infrastructure, and exposure - WHOIS, certificate transparency, subdomains, open ports, cloud footprint, leaked credentials, typosquat domains, and relevant news - and writes the results to a Markdown or PDF report. Every data source it uses beyond WHOIS and certificate transparency is optional: Farsight works with zero configuration, and adding API keys unlocks deeper results rather than being required to run at all.

## Requirements

- **Python 3.10 or newer.** Farsight drops support for anything older; if you're on an older interpreter, the install will simply fail its dependency resolution.
- On Windows, activate the virtualenv and then use the `python` command, not `python3`. `python3` on Windows frequently resolves to the Microsoft Store Python stub rather than your venv's interpreter, which reports Farsight's dependencies as missing even though `pip install` succeeded cleanly.

## Install

The fastest path is PyPI:

```bash
pip install farsight-recon
```

The distribution on PyPI is named `farsight-recon` (the plain `farsight` name was already taken), but it installs the same `farsight` command - nothing about how you invoke it changes.

With [Poetry](https://python-poetry.org/):

```bash
poetry add farsight-recon
```

Or run from source, if you want to modify the tool or track `dev`:

```bash
git clone https://github.com/seedon198/Farsight.git
cd Farsight
python3 -m venv venv
source venv/bin/activate      # macOS/Linux
# venv\Scripts\activate       # Windows (cmd)
# venv\Scripts\Activate.ps1   # Windows (PowerShell)
pip install -r requirements.txt
```

When running from source, swap `farsight` for `python -m farsight` in every command in this documentation.

## Your first scan

```bash
farsight scan example.com
```

With no flags, this runs only the **Organization Discovery** and **Recon & Asset Discovery** modules (they're always enabled - see [CLI Reference](/docs/cli-reference/) for why) and writes `./report.md`. That's deliberately the minimal, fast path: WHOIS, certificate transparency, passive DNS, DNS enumeration, subdomain discovery, and a port scan, with no API keys and no destructive traffic against the target.

To bring in everything the tool can do:

```bash
farsight scan example.com --all --verbose
```

`--all` enables every module (adds Extended Attack Surface, Threat Intelligence, Typosquatting Detection, and News Monitoring on top of the two always-on modules), and `--verbose` prints a live, color-coded summary per module plus which of the optional API providers are currently configured.

<div class="cast-player" data-src="/assets/docs/casts/scan-basic.cast" data-cols="84" data-rows="34"></div>

## Adding API keys (optional)

Every third-party provider Farsight can use - Shodan, Censys, SecurityTrails, VirusTotal, IntelX, LeakPeek, Crunchbase, GrayHatWarfare, FullHunt, Netlas, ZoomEye, Onyphe - is opt-in. Copy `.env.example` to `.env` in your working directory and fill in whichever keys you have; Farsight auto-loads it via `python-dotenv` on startup. See [Configuration & API Keys](/docs/configuration/) for the full provider table and what each one unlocks.

## The web UI

If you'd rather watch a scan run in a browser than read a terminal scroll by, install the optional web extra:

```bash
pip install -r requirements-web.txt
python -m farsight web
```

This opens `http://127.0.0.1:8000` with live per-module progress over a WebSocket, running stat tiles, an attack-surface graph, and an in-browser report. It binds to loopback only and has no authentication, so don't expose it beyond your own machine. See the [Web UI Guide](/docs/web-ui/) for a full tour.

## Where to go next

- [CLI Reference](/docs/cli-reference/) - every flag `scan` and `web` support
- [Architecture](/docs/architecture/) - how a scan actually flows through the module pipeline
- Module deep-dives - [Organization Discovery](/docs/module-org-discovery/), [Recon & Asset Discovery](/docs/module-recon/), [Extended Attack Surface](/docs/module-attack-surface/), [Threat Intelligence](/docs/module-threat-intel/), [Typosquatting Detection](/docs/module-typosquat/), [News Monitoring](/docs/module-news/)
