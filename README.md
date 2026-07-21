<div align="center">

<table>
<tr>
<td align="center" width="50%">

### DEFCON 34

<a href="https://www.appsecvillage.com/events/dc-2026/farsight-turning-osint-into-actionable-attack-surface-intelligence-1206456">
<img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/appsecvillage-logo.png" alt="AppSec Village" height="64"/>
</a>

<sub>🗓️ Aug 6–9, 2026 &nbsp;•&nbsp; Las Vegas &nbsp;•&nbsp; Upcoming</sub>

**[Farsight: Turning OSINT into Actionable Attack Surface Intelligence](https://www.appsecvillage.com/events/dc-2026/farsight-turning-osint-into-actionable-attack-surface-intelligence-1206456)**

</td>
<td align="center" width="50%">

### BLACKHAT 2025

<a href="https://www.blackhat.com/sector/2025/arsenal/schedule/index.html#farsight-cli-based-recon-and-threat-intelligence-framework-47707">
<img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/blackhat-logo.png" alt="Black Hat" height="64"/>
</a>

<sub>🎯 Oct 1–2, 2025 &nbsp;•&nbsp; Toronto &nbsp;•&nbsp; Presented</sub>

**[Arsenal: CLI-Based Recon and Threat Intelligence Framework](https://www.blackhat.com/sector/2025/arsenal/schedule/index.html#farsight-cli-based-recon-and-threat-intelligence-framework-47707)**

</td>
</tr>
</table>

</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/logo.svg" alt="FARSIGHT Logo" width="100%"/>
</p>

# FARSIGHT

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/seedon198/Farsight?style=for-the-badge&cacheSeconds=3600)](https://github.com/seedon198/Farsight/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/seedon198/Farsight/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/seedon198/Farsight/actions)
[![Last Commit](https://img.shields.io/github/last-commit/seedon198/Farsight?style=for-the-badge)](https://github.com/seedon198/Farsight/commits/main)
[![Documentation](https://img.shields.io/badge/docs-farsight.click-ff3b30?style=for-the-badge)](https://farsight.click/docs/)

**A fast, modular CLI recon and threat-intelligence framework. Works with or without API keys.**

📖 **Full documentation, architecture, module internals, and a web UI tour: [farsight.click/docs](https://farsight.click/docs/)**

<p align="center">
  <img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/demo.gif" alt="FARSIGHT demo: scanning a domain from the CLI" width="100%"/>
</p>

## Features

- **Organization Discovery:** WHOIS, certificate transparency, passive DNS, related domains, acquisitions (M&A) via Wikidata, news, and optional Crunchbase
- **Recon & Asset Discovery:** DNS enumeration, subdomain discovery, async port scanning
- **Extended Attack Surface:** ASN/netblock discovery, AWS/Azure/GCP cloud-IP tagging, exposed storage bucket search, and Shodan/FullHunt/Netlas/ZoomEye/Onyphe org/keyword search -- finds company-owned assets certificate transparency alone won't surface
- **Threat Intelligence:** leak detection, credential exposure, dark web mentions, email reputation
- **Typosquatting Detection:** domain permutation, content similarity, risk scoring
- **News Monitoring:** relevance-scored news tracking across multiple sources
- **Reporting:** Markdown and PDF output with executive summaries
- **API-optional:** works out of the box; add keys (Shodan, Censys, VirusTotal, ...) for deeper results

## Install

```bash
pip install farsight-recon
```

(The PyPI distribution is named `farsight-recon` since `farsight` was already taken, but it installs the same `farsight` command.)

With [Poetry](https://python-poetry.org/):

```bash
poetry add farsight-recon
```

Or run from source:

```bash
git clone https://github.com/seedon198/Farsight.git
cd Farsight
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate    # Windows (cmd)
# venv\Scripts\Activate.ps1  # Windows (PowerShell)
pip install -r requirements.txt
```

Requires Python 3.10+. After activation, use the `python` command (not `python3`) to run FARSIGHT - on Windows, `python3` often resolves to the Microsoft Store Python stub instead of your venv, which will report modules as missing even though `pip install` succeeded.

## Usage

```bash
# Basic scan (org discovery + recon)
farsight scan example.com

# Everything, verbose
farsight scan example.com --all --verbose

# Specific modules, PDF output
farsight scan example.com -m org -m threat --output report.pdf

# Include extended attack surface discovery (ASN/netblock/cloud/bucket search)
farsight scan example.com --attack-surface --verbose
```

Running from source instead of a pip install? Swap `farsight` for `python -m farsight` in any command above.

Run `farsight scan --help` for the full option list.

## Web UI

A local-only web UI wraps the same scan modules with a live-progress browser view:

```bash
pip install -r requirements-web.txt
python -m farsight web
```

Opens a browser at `http://127.0.0.1:8000` with real-time module progress, live stats, and an in-browser report with Markdown/PDF download. Binds to loopback only - there's no authentication, so don't expose it beyond your own machine. Run `python -m farsight web --help` for options.

<p align="center">
  <img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/web-ui-scan.png" alt="FARSIGHT web UI: scan form with live stats" width="100%"/>
</p>

<table>
<tr>
<td width="55%"><img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/web-ui-graph.png" alt="FARSIGHT web UI: attack surface graph"/></td>
<td width="45%"><img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/web-ui-typosquat.png" alt="FARSIGHT web UI: typosquat watch grid"/></td>
</tr>
</table>

<p align="center">
  <img src="https://raw.githubusercontent.com/seedon198/Farsight/main/docs/assets/web-ui-report.png" alt="FARSIGHT web UI: in-browser report" width="100%"/>
</p>

## API Keys (optional)

FARSIGHT works with zero configuration -- every source below is optional and just unlocks deeper results from that provider. Copy [`.env.example`](.env.example) to `.env` and fill in whichever keys you have.

```bash
export FARSIGHT_SHODAN_API_KEY="..."
export FARSIGHT_CENSYS_API_KEY="..."
export FARSIGHT_SECURITYTRAILS_API_KEY="..."
export FARSIGHT_VIRUSTOTAL_API_KEY="..."
export FARSIGHT_INTELX_API_KEY="..."
export FARSIGHT_LEAKPEEK_API_KEY="..."
export FARSIGHT_CRUNCHBASE_API_KEY="..."
export FARSIGHT_GRAYHATWARFARE_API_KEY="..."
export FARSIGHT_FULLHUNT_API_KEY="..."
export FARSIGHT_NETLAS_API_KEY="..."
export FARSIGHT_ZOOMEYE_API_KEY="..."
export FARSIGHT_ONYPHE_API_KEY="..."
```

| Key | Used for | Why add it |
|---|---|---|
| `FARSIGHT_SHODAN_API_KEY` | Recon: internet-wide host/device search; attack surface: org/keyword search | Surfaces exposed services and banners for the target's hosts beyond an active port scan; also powers `org:`/keyword search for assets certificate transparency never surfaces |
| `FARSIGHT_CENSYS_API_KEY` | Recon: host and certificate search | Cross-checks Shodan-style host data; certificate search needs a paid/org Censys tier |
| `FARSIGHT_SECURITYTRAILS_API_KEY` | Org discovery: subdomains and org-wide domain search | Finds subdomains and related domains beyond what crt.sh and passive DNS surface for free |
| `FARSIGHT_VIRUSTOTAL_API_KEY` | Recon: subdomain enumeration | Adds another passive subdomain source alongside crt.sh, RapidDNS, and DNSDB |
| `FARSIGHT_INTELX_API_KEY` | Threat intel: dark web mentions, phonebook, documents | Without it, dark web checks fall back to a weaker free method; with it you get IntelX's phonebook and document search too |
| `FARSIGHT_LEAKPEEK_API_KEY` | Threat intel: leaked credential search | Checks discovered emails against known breach data |
| `FARSIGHT_CRUNCHBASE_API_KEY` | Org discovery: acquisitions (M&A) | Crunchbase has had no free tier since ~2020, so this is paid/opt-in; acquisition discovery already works without it via free Wikidata + news sources, this just adds a third, higher-confidence source |
| `FARSIGHT_GRAYHATWARFARE_API_KEY` | Attack surface: exposed S3/Azure/GCS/DigitalOcean bucket search | Finds publicly exposed cloud storage buckets matching the target org/subsidiary names; free tier caps daily query volume, so the module budgets queries per scan |
| `FARSIGHT_FULLHUNT_API_KEY` | Attack surface: organization-based host search | A second, purpose-built attack-surface engine to cross-check Shodan's org/keyword results against |
| `FARSIGHT_NETLAS_API_KEY` | Attack surface: organization-based host search | Another Shodan/Censys-style internet scan engine, broadening host coverage beyond a single source |
| `FARSIGHT_ZOOMEYE_API_KEY` | Attack surface: organization-based host search | Adds coverage of Chinese-hosted infrastructure that Western-centric scanners see less of |
| `FARSIGHT_ONYPHE_API_KEY` | Attack surface: organization-based host search | Aggregates internet-scan and threat-intel data as a fifth cross-check source |

The attack surface module's ASN/netblock discovery (via BGPView and bgp.he.net, enriched with RIPEstat) and AWS/Azure/GCP cloud-IP tagging (via the providers' own published IP ranges) run automatically with **none of the five keys above configured** -- they're free and keyless, and already surface company-owned netblocks and cloud-hosted assets that never carry a matching certificate hostname. The keys just add more org/keyword search sources on top.

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
