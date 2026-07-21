---
title: Configuration & API Keys
description: Every supported provider, environment variable, and tunable setting.
section: Reference
order: 3
---

All configuration lives in `farsight/config.py`. Farsight works with zero configuration - every setting below has a working default, and every API key below is optional.

## .env loading

Farsight auto-loads a `.env` file from your **current working directory** via `python-dotenv`'s `find_dotenv(usecwd=True)` - this anchors the search at wherever you run `farsight` from, not the package's install location, so it works the same whether you installed from PyPI or are running from source. Copy `.env.example` to `.env` and fill in whichever keys you have.

## API keys

| Key | Used for | Why add it |
|---|---|---|
| `FARSIGHT_SHODAN_API_KEY` | Recon: internet-wide host/device search; attack surface: org/keyword search | Surfaces exposed services and banners for the target's hosts beyond an active port scan; also powers `org:`/keyword search for assets certificate transparency never surfaces |
| `FARSIGHT_CENSYS_API_KEY` | Recon: host search | Cross-checks Shodan-style host data. Note: Censys's *certificate* search specifically needs a paid/organization tier - Farsight detects a configured-but-free-tier key and skips that call entirely rather than failing on every scan |
| `FARSIGHT_SECURITYTRAILS_API_KEY` | Org discovery: subdomains and org-wide domain search | Finds subdomains and related domains beyond what crt.sh and passive DNS surface for free |
| `FARSIGHT_VIRUSTOTAL_API_KEY` | Recon: subdomain enumeration | Adds another passive subdomain source alongside crt.sh, RapidDNS, and DNSDB |
| `FARSIGHT_INTELX_API_KEY` | Threat intel: dark web mentions, phonebook, documents | Without it, dark web checks fall back to a weaker pattern-matching method against a hardcoded breach list; with it you get IntelX's phonebook and document search too. Results are cached locally since IntelX bills per search, not per result fetch - see [Threat Intelligence](/docs/module-threat-intel/) |
| `FARSIGHT_LEAKPEEK_API_KEY` | Threat intel: leaked credential search | Checks discovered emails against known breach data |
| `FARSIGHT_CRUNCHBASE_API_KEY` | Org discovery: acquisitions (M&A) | Crunchbase has had no free tier since ~2020, so this is paid/opt-in; acquisition discovery already works without it via free Wikidata + news sources - this just adds a third, independently-sourced confirmation |
| `FARSIGHT_GRAYHATWARFARE_API_KEY` | Attack surface: exposed S3/Azure/GCS/DigitalOcean bucket search | Finds publicly exposed cloud storage buckets matching the target org/subsidiary names; free tier caps daily query volume, so the module budgets queries per scan |
| `FARSIGHT_FULLHUNT_API_KEY` | Attack surface: organization-based host search | A second, purpose-built attack-surface engine to cross-check Shodan's org/keyword results against |
| `FARSIGHT_NETLAS_API_KEY` | Attack surface: organization-based host search | Another Shodan/Censys-style internet scan engine, broadening host coverage beyond a single source |
| `FARSIGHT_ZOOMEYE_API_KEY` | Attack surface: organization-based host search | Adds coverage of Chinese-hosted infrastructure that Western-centric scanners see less of |
| `FARSIGHT_ONYPHE_API_KEY` | Attack surface: organization-based host search | Aggregates internet-scan and threat-intel data as a fifth cross-check source |

The [Extended Attack Surface](/docs/module-attack-surface/) module's ASN/netblock discovery (BGPView + bgp.he.net, enriched with RIPEstat) and AWS/Azure/GCP cloud-IP tagging (via the providers' own published IP ranges) run automatically with **none** of the five attack-surface keys configured - they're free and keyless. The keys just add more org/keyword search sources on top.

## Rate limits (requests per minute)

Every API call goes through a per-provider `RateLimiter`. These are the actual configured limits, not aspirational targets - a deep scan against a domain with many query keywords will visibly slow down rather than exceed them:

| Provider | Requests/minute |
|---|---|
| Shodan | 60 |
| Censys | 120 |
| VirusTotal | 4 |
| Crunchbase | 30 |
| GrayHatWarfare | 30 |
| FullHunt | 30 |
| Netlas | 60 |
| ZoomEye | 30 |
| Onyphe | 30 |
| (any other/default) | 60 |

VirusTotal's limit of 4/minute reflects its free-tier API quota directly - if you have a paid VirusTotal key, note that Farsight doesn't currently distinguish tiers; the conservative free-tier limit applies regardless.

## Tunable settings

These aren't currently exposed as CLI flags (except where noted) - they live in `DEFAULT_CONFIG` and would need a code change to adjust, but are worth knowing about when interpreting results:

| Setting | Default | Effect |
|---|---|---|
| `timeout` | `30` (seconds) | Global HTTP request timeout. Exposed as `farsight scan --timeout` |
| `max_concurrent_requests` | `10` | Max concurrent requests. Exposed as `farsight scan --concurrency` |
| `dns_resolver` | `1.1.1.1` | DNS resolver used for bulk resolution |
| `port_scan_timeout` | `2` (seconds) | Per-port connect timeout for the fallback (non-masscan) scanner |
| `masscan_rate` | `10000` (packets/sec) | Masscan's discovery-pass rate, if masscan is installed |
| `default_ports` | 20-port list | Ports checked at scan depth 1 (see [Recon](/docs/module-recon/) for the full list and the 35-port depth-≥2 expansion) |
| `typosquat_threshold` | `80` | Minimum risk score for a typosquat candidate to appear in results (candidates above 85% raw string similarity are kept regardless - see [Typosquatting Detection](/docs/module-typosquat/)) |
| `news_results_limit` | `10` | Max news articles returned |
| `acquisition_news_lookback_days` | `730` (2 years) | How far back news-based acquisition detection searches |
| `intelx_cache_ttl` | `21600` (6 hours) | How long a cached IntelX search result is considered fresh |
| `attack_surface_max_keywords` | `5` | Cap on org/subsidiary name keywords queried per scan, protecting free-tier query budgets |

## Directories

- `PROJECT_ROOT` - resolved relative to the installed package location
- `REPORTS_DIR` - `./reports`, created automatically if missing
- `CACHE_DIR` - `./cache`, used by the IntelX search cache
