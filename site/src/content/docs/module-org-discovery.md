---
title: Organization Discovery
description: WHOIS, certificate transparency, passive DNS, and acquisition mapping.
section: Modules
order: 1
---

Implemented in `farsight/modules/org_discovery.py`, class `OrgDiscovery`. Always runs — it's one of the two modules (with Recon) enabled by default regardless of flags, because everything downstream needs its output: the org name and acquisitions list are fed directly into [Extended Attack Surface](/docs/module-attack-surface/)'s keyword search.

## Two-phase execution

**Phase 1** runs WHOIS lookup and certificate-transparency search (crt.sh) concurrently — they don't depend on each other, but everything in phase 2 needs WHOIS's resolved organization name, so phase 1 must fully complete first.

**Phase 2** is depth-gated:

- **Depth ≥2**: passive DNS lookup (RapidDNS + DNSDB.io scraping), SecurityTrails subdomain/org search (if configured), Wikidata acquisition lookup, news-based acquisition lookup, Crunchbase acquisition lookup (if configured)
- **Depth ≥3**: attempts Censys certificate search — which is **always skipped**, even when a Censys key is configured, because Censys's certificate search endpoint requires a paid/organization tier; free personal-access-token accounts get a 403 telling you to use their Platform UI instead. Farsight logs this and moves on rather than retrying a call that can never succeed on a free key.

## Acquisition discovery: three sources, one confidence model

Farsight tracks corporate acquisitions (M&A relationships) because a target's subsidiaries are often where the real attack surface lives — a well-secured parent company can still be exposed through a recently-acquired subsidiary that hasn't been folded into the parent's security program yet.

1. **Wikidata** (free, always tried at depth ≥2): a SPARQL query against properties P355 (subsidiary), P127 (owned by), and P749 (parent organization).
2. **News-derived acquisitions** (free, depth ≥2): searches news via the [News Monitoring](/docs/module-news/) module for "X acquires Y" / "acquired by" patterns within a configurable lookback window (`acquisition_news_lookback_days`, default 730 days). Because a regex match on a news headline is weak evidence on its own, each candidate name is passed through `_confirm_domain_for_org`: Farsight guesses a `.com` domain from the company name (stripping to alphanumerics), runs a WHOIS lookup against that guess, and only accepts the guess if the WHOIS organization field shares a significant token (>2 characters) with the candidate name. If confirmation fails, the acquisition is still recorded, just without a confirmed domain and at lower confidence — Farsight doesn't discard a plausible lead just because it can't verify a domain guess.
3. **Crunchbase** (paid, depth ≥2, only if `FARSIGHT_CRUNCHBASE_API_KEY` is set): resolved via a domain-search call, then an autocomplete permalink lookup. Crunchbase has had no free tier since roughly 2020, so this is purely an opt-in third source layered on top of the two free ones — acquisition discovery already works without it.

Each acquisition record carries a `source` (`wikidata`, `news`, or `crunchbase`) and a `relationship`, so a report reader can judge how much to trust a given entry rather than treating all acquisitions as equally certain.

## Domain vs. subdomain classification

Every domain surfaced by certificate transparency, passive DNS, or API results gets deduplicated and classified: anything ending in `.<target-domain>` (or containing `.<base-domain-suffix>`, e.g. `.sony.com`) is a **subdomain** of the target; anything else is a separate **related domain** (a different registered domain entirely — a common pattern for acquired brands that kept their own domain). This split matters downstream: [Recon](/docs/module-recon/)'s port scanning and DNS enumeration work over both lists, but they mean different things in a report — a related domain is a separate organizational asset, not just a subdomain of the one you scanned.

## Output shape

```json
{
  "target_domain": "example.com",
  "whois": { "org": "...", "registrar": "...", "creation_date": "..." },
  "certificate_transparency": ["www.example.com", "mail.example.com"],
  "passive_dns": ["..."],
  "related_domains": ["examplecorp.net"],
  "discovered_subdomains": ["www.example.com", "shop.example.com"],
  "acquisitions": [
    { "org_name": "Acquired Co", "relationship": "acquired", "domain": "acquiredco.com", "source": "wikidata", "confidence": "high" }
  ]
}
```

This feeds [Extended Attack Surface](/docs/module-attack-surface/) directly: `org_name` and `acquisitions` become the keyword list for org/keyword search engines, and `discovered_subdomains`' resolved IPs (via Recon) become the known-IP list for cloud tagging.
