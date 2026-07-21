---
title: Extended Attack Surface
description: ASN/netblock discovery, cloud-IP tagging, and exposed bucket search.
section: Modules
order: 3
---

Implemented in `farsight/modules/attack_surface.py`, class `AttackSurface`. Enabled with `--attack-surface`/`-a` (or `--all`/`--modules attack_surface`). Runs third in the pipeline, after [Organization Discovery](/docs/module-org-discovery/) and [Recon](/docs/module-recon/) — see [Architecture](/docs/architecture/) for why the ordering matters.

## Why this module exists separately from certificate transparency

The module's own docstring states the rationale directly: certificate transparency (in Org Discovery) "only surfaces assets that carry a public cert with a hostname matching the target domain." This module finds company-owned assets that never show up that way — raw IPs and netblocks identified by ASN/org ownership instead of hostname, cloud-hosted resources tagged by IP range rather than DNS, and exposed object storage buckets. **False positives are an explicitly accepted tradeoff** — the design goal is coverage, not precision, on the theory that a security team can dismiss a false positive in seconds but can't investigate an asset it never saw.

## Inputs from earlier modules

`discover()` takes `org_name` and `subsidiaries` from Org Discovery's results, and `known_ips` from Recon's resolved A records. This is the one module in the pipeline that's explicitly wired to consume prior output rather than only the raw domain — see [Architecture](/docs/architecture/) for the full data-flow diagram.

## Keyword list construction

The org/keyword search phase needs search terms, not just a domain. `_build_keyword_list` starts with the primary org name (WHOIS org, or a domain-derived guess if WHOIS didn't resolve one), then adds subsidiary/acquisition names from Org Discovery — capped at `attack_surface_max_keywords` (default 5). The cap exists specifically to protect free-tier query budgets: an org with a long acquisition history could otherwise generate dozens of keyword-search calls against rate-limited providers for a single scan.

## Keyless discovery (runs at any depth, no API key needed)

Two sources run unconditionally:

1. **ASN and netblock discovery**: searches the free [BGPView API](https://bgpview.io/api) by organization name, falling back to scraping bgp.he.net's search page if BGPView is unavailable. Matched ASNs are enriched with RIPEstat holder-name data, then their announced netblocks are fetched (capped at 15 ASNs per scan — `_MAX_ASNS_FOR_PREFIX_LOOKUP` — since a common-word org name can match dozens of ASNs, and each one costs a bgp.he.net scrape for its prefix list; this cap is a safety valve, not a user-facing setting).
2. **Cloud-IP tagging**: `farsight/utils/cloud_ranges.py` downloads and caches (for the process lifetime — these files are tens of thousands of prefixes and change at most weekly) AWS, Azure, and GCP's own published IP-range files, and checks every netblock this module found — plus every `known_ip` passed in from Recon — for containment via Python's `ipaddress` module. A matching IP gets tagged with which cloud provider (and often region) owns that range.

Both of these need zero API keys — they're the reason the module's ASN/netblock/cloud sections aren't empty even on a completely keyless install.

## Keyed discovery (depth ≥2 only)

For every keyword, Farsight fans out to whichever of these providers are configured: Shodan (both an org-filtered search and a plain keyword search), GrayHatWarfare (exposed S3/Azure/GCS/DigitalOcean bucket search), FullHunt, Netlas, ZoomEye, and Onyphe (four purpose-built attack-surface/internet-scan engines, each a cross-check against the others rather than a primary source). None of the five keyed providers are required for the module to produce useful output — see [Configuration & API Keys](/docs/configuration/) for what each one specifically adds.

## Output shape

```json
{
  "target": "example.com",
  "keywords_used": ["Example Corp", "Acquired Co"],
  "asns": [{ "asn": "AS64500", "holder": "EXAMPLE-CORP", "source": "bgpview" }],
  "total_asns": 1,
  "netblocks": [{ "cidr": "203.0.113.0/24", "asn": "AS64500", "cloud": null }],
  "total_netblocks": 1,
  "exposed_buckets": [],
  "tagged_known_ips": [{ "ip": "3.5.140.2", "cloud": "aws" }],
  "cloud_summary": { "aws": 1, "azure": 0, "gcp": 0 }
}
```

The web UI's Extended Attack Surface panel renders this directly — cloud badges, then buckets/ASNs/netblocks tables. See the [Web UI Guide](/docs/web-ui/) for a screenshot, and note that on a domain with no real public cloud footprint or ASN presence (e.g. a small site with no BGP-announced infrastructure of its own), every one of these tables legitimately shows empty — that's correct behavior, not a broken module.
