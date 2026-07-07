<div align="center">

<table>
<tr>
<td align="center" width="50%">

### DEFCON 34

<a href="https://sessionize.com/adlin-seedon-dsouza/">
<img src="docs/assets/appsecvillage-logo.png" alt="AppSec Village" height="64"/>
</a>

<sub>🗓️ Aug 6–9, 2026 &nbsp;•&nbsp; Las Vegas &nbsp;•&nbsp; Upcoming</sub>

**[Farsight: Turning OSINT into Actionable Attack Surface Intelligence](https://sessionize.com/adlin-seedon-dsouza/)**

</td>
<td align="center" width="50%">

### BLACKHAT 2025

<a href="https://www.blackhat.com/sector/2025/arsenal/schedule/index.html#farsight-cli-based-recon-and-threat-intelligence-framework-47707">
<img src="docs/assets/blackhat-logo.png" alt="Black Hat" height="64"/>
</a>

<sub>🎯 Oct 1–2, 2025 &nbsp;•&nbsp; Toronto &nbsp;•&nbsp; Presented</sub>

**[Arsenal: CLI-Based Recon and Threat Intelligence Framework](https://www.blackhat.com/sector/2025/arsenal/schedule/index.html#farsight-cli-based-recon-and-threat-intelligence-framework-47707)**

</td>
</tr>
</table>

</div>

<p align="center">
  <img src="docs/assets/logo.svg" alt="FARSIGHT Logo" width="100%"/>
</p>

# FARSIGHT

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/seedon198/Farsight?style=for-the-badge&cacheSeconds=3600)](https://github.com/seedon198/Farsight/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/seedon198/Farsight/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/seedon198/Farsight/actions)
[![Style: black](https://img.shields.io/badge/style-black-000000.svg?style=for-the-badge)](https://github.com/psf/black)
[![Last Commit](https://img.shields.io/github/last-commit/seedon198/Farsight?style=for-the-badge)](https://github.com/seedon198/Farsight/commits/main)

**A fast, modular CLI recon and threat-intelligence framework. Works with or without API keys.**

<p align="center">
  <img src="docs/assets/demo.gif" alt="FARSIGHT demo: scanning a domain from the CLI" width="100%"/>
</p>

## Features

- **Organization Discovery:** WHOIS, certificate transparency, passive DNS, related domains
- **Recon & Asset Discovery:** DNS enumeration, subdomain discovery, async port scanning
- **Threat Intelligence:** leak detection, credential exposure, dark web mentions, email reputation
- **Typosquatting Detection:** domain permutation, content similarity, risk scoring
- **News Monitoring:** relevance-scored news tracking across multiple sources
- **Reporting:** Markdown and PDF output with executive summaries
- **API-optional:** works out of the box; add keys (Shodan, Censys, VirusTotal, ...) for deeper results

## Install

```bash
git clone https://github.com/seedon198/Farsight.git
cd Farsight
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.10+.

## Usage

```bash
# Basic scan (org discovery + recon)
python -m farsight scan example.com

# Everything, verbose
python -m farsight scan example.com --all --verbose

# Specific modules, PDF output
python -m farsight scan example.com -m org -m threat --output report.pdf
```

Run `python -m farsight scan --help` for the full option list.

## API Keys (optional)

FARSIGHT works with zero configuration. Set these for deeper results:

```bash
export FARSIGHT_SHODAN_API_KEY="..."
export FARSIGHT_CENSYS_API_KEY="..."
export FARSIGHT_SECURITYTRAILS_API_KEY="..."
export FARSIGHT_VIRUSTOTAL_API_KEY="..."
export FARSIGHT_INTELX_API_KEY="..."
export FARSIGHT_LEAKPEEK_API_KEY="..."
```

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/
```

Contributions welcome: fork, branch, open a PR.

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

For authorized security assessments only. Always get permission before scanning a domain or network you don't own.
