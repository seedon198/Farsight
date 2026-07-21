---
title: Architecture
description: How a scan flows through Farsight's module pipeline.
section: Reference
order: 2
---

Farsight is not six independent tools glued behind one CLI - the modules run in a fixed sequence, and later modules consume the output of earlier ones. Understanding that sequence explains both why the module order is fixed and why some flags (like `--attack-surface` without `org`) still produce useful output even though `org`/`recon` weren't explicitly requested (they always run).

## The pipeline

```
 org discovery ──▶ recon ──▶ attack surface ──▶ threat intel ──▶ typosquat ──▶ news
      │                │            ▲
      │ org_name,      │ known_ips  │
      │ acquisitions   │ (resolved  │
      │ (subsidiaries) │  A records)│
      └────────────────┴────────────┘
```

1. **Org Discovery** runs first and unconditionally. It establishes the target's identity: WHOIS org name, related domains, certificate-transparency hostnames, and any acquisitions/subsidiaries (via Wikidata, news, optional Crunchbase).
2. **Recon** runs second, also unconditionally. It resolves DNS records for the domains org discovery surfaced, enumerates subdomains, and port-scans the results.
3. **Extended Attack Surface**, if enabled, runs third and is explicitly fed data from the first two: `org_name` and `acquisitions` (as a keyword list for org/keyword search engines) come from org discovery, and `known_ips` (every resolved A record) comes from recon, so cloud-IP tagging can check addresses Farsight already resolved without a second DNS pass.
4. **Threat Intelligence**, **Typosquatting Detection**, and **News Monitoring** run last, in that order, each independently of the others.

This sequence is implemented twice - once in `farsight/cli/scan.py`'s `run_scan()` for the CLI, and once in `farsight/web/orchestrator.py`'s `run_scan_with_events()` for the web UI - deliberately not shared. The orchestrator's module docstring explains why: it "mirrors `run_scan()`'s module sequence and wiring without importing or modifying that module, so the CLI path (stabilized separately) carries zero additional risk from this code." The one intentional behavioral difference: the web orchestrator wraps each module in its own try/except, so one module's failure surfaces as a `module_error` event without aborting the rest of the scan - appropriate for a live demo, where degrading gracefully matters more than failing loudly.

## Two entry points, one report writer

Both the CLI and the web UI end at the same place: `farsight/modules/report_writer.py`'s `ReportWriter.generate_report()`, which builds the Markdown report (and optionally converts it to PDF). The web UI's `finalize_scan()` calls this exact function - see [Reports](/docs/reports/) for what it produces.

## Demo replay

`farsight web --demo` doesn't take a different code path through the modules - it takes a different *data* path. `farsight/web/replay.py`'s `replay_scan()` replays a captured JSON fixture (by default `farsight/web/fixtures/demo_scan_example.com.json`) through the **same event sequence** (`MODULE_ORDER`, the same summary builders, the same `finalize_scan()`) that a live scan produces, with artificial pacing between modules. The frontend cannot distinguish a replay from a live scan by its event stream - that's a deliberate design constraint, not an accident, so the demo mode is genuinely useful for showing the UI at a venue with an untrusted network. Fixtures are captured with the standalone `scripts/capture_demo_fixture.py <domain>` script (not an installed CLI command).

## Concurrency and safety

The web UI enforces a **single concurrent scan** (`farsight/web/scan_manager.py`'s `ScanManager`, a `Lock`-guarded flag) rather than running one scan per client connection. The reason is `DEFAULT_CONFIG` mutation: `--timeout`/`--concurrency` (and the CLI equivalents) mutate a shared module-level config dict rather than threading a config object through every call, which isn't safe under concurrent scans. Attempting to start a second scan while one is running gets a `scan_rejected` event, not a queued request.

## Retry, rate limiting, and caching

Every outbound API call goes through `farsight/utils/api_handler.py`'s `APIHandler`, which layers two cross-cutting concerns on top of the raw request:

- **Rate limiting**: a `RateLimiter` (`farsight/utils/common.py`) enforces a per-provider sliding-window limit (e.g. Shodan 60 req/min, VirusTotal 4 req/min, Censys 120 req/min - see [Configuration](/docs/configuration/) for the full table), so a deep scan against a domain with many candidates doesn't blow through a provider's free-tier quota mid-scan.
- **Retry with backoff**: a `@retry` decorator wraps API calls with 3 retries, exponential backoff, and jitter, so a single transient timeout or 5xx doesn't fail an entire module.

One provider gets a third layer: **IntelX search caching** (`farsight/utils/intelx_cache.py`), a disk-backed cache keyed on the search parameters. IntelX bills a credit per *search*, but fetching results from an existing search ID is free - so identical repeat queries (common when iterating on a scan against the same domain) reuse the cached search ID instead of re-billing. The cache TTL defaults to 6 hours (`intelx_cache_ttl`).

## Keyless attack-surface discovery

The Extended Attack Surface module's core value proposition - ASN/netblock ownership and cloud-IP tagging - needs **no API key at all**. `farsight/utils/cloud_ranges.py` downloads and caches (for the process lifetime) AWS/Azure/GCP's own published IP-range files, and ASN discovery uses the free BGPView API with an bgp.he.net HTML-scrape fallback, enriched with RIPEstat holder-name lookups. The five keyed providers (Shodan, GrayHatWarfare, FullHunt, Netlas, ZoomEye, Onyphe) only add *more* org/keyword search sources on top - they're not required for the module to find anything.

## Why masscan is optional, not required

`farsight/utils/masscan.py` prefers the `masscan` binary if it's installed (fast, but needs elevated privileges on most systems), and falls back to a pure-Python async socket scanner (`PortScanner` in `farsight/utils/dns.py`) if it isn't. This means Farsight's port scanning works out of the box on a locked-down machine, just slower - masscan is a performance optimization, not a hard dependency.
