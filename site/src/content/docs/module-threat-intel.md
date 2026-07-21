---
title: Threat Intelligence
description: Leak detection, credential exposure, dark web mentions, and email reputation.
section: Modules
order: 4
---

Implemented in `farsight/modules/threat_intel.py`, class `ThreatIntel`. Enabled with `--threat-intel`/`-t` (or `--all`/`--modules threat`).

## What always runs

Two checks run regardless of depth or configuration:

- **PhoneBook.cz scraping** — a public source for leaked emails associated with the domain, no API key needed.
- **Dark web alternative check** (`_check_dark_web_alternative`) — runs automatically whenever IntelX **isn't** configured. This is a pattern-matching fallback against a hardcoded list of historical breaches, explicitly labeled with low/medium confidence in its output rather than presented as equivalent to a real dark-web search. It exists so the module still produces *something* on a fully keyless install, not nothing.

## Depth-gated checks

- **Depth ≥2**: if IntelX is configured, runs a proper IntelX search (leaks/pastes/darknet mentions) and an IntelX phonebook search (related selectors — other emails, domains, or identifiers linked to the target); if LeakPeek is configured and emails are available, checks each against known breach data; computes [email reputation](#email-reputation-scoring) for every email found so far.
- **Depth 3**: if IntelX is configured, additionally searches its `documents` bucket. If the scan found domain-associated emails but none were explicitly provided, checks up to the first 3 against HaveIBeenPwned as a supplementary pass — capped at 3 specifically to avoid overloading that check for domains with many discovered emails.

## The IntelX cache: avoiding repeat credit spend

IntelX bills a credit per **search**, but fetching results for an existing search ID is free. `_cached_intelx_search` (backed by `farsight/utils/intelx_cache.py`) hashes the query parameters to a cache key: an identical repeat query either serves already-cached results directly, or — if the cached entry only has a search ID but no fresh results — re-uses that search ID against the free result endpoint instead of starting a new (billed) search. The cache defaults to a 6-hour TTL (`intelx_cache_ttl`). This matters in practice: iterating on a scan against the same domain during development, or re-running a scan you already ran that day, doesn't silently burn through a limited IntelX quota.

## Email reputation scoring

`get_email_reputation()` computes a 0–100 risk score per discovered email, independent of any external breach-database lookup — this is a heuristic based on the email and its domain alone:

```
score += 40  if the domain is < 30 days old (WHOIS creation date)
score += 20  if the domain is 30-90 days old
score += 30  if the domain is a known disposable/temp-mail provider
score += 15  if the username is more than 50% digits
score += 10  if the username is a generic role account (admin, info,
             sales, support, noreply, contact)
```

Score bands map to a label: `>=70` high risk, `>=40` medium risk, `>=10` low risk, otherwise good. A brand-new domain paired with a disposable-provider username can hit 70+ purely from those two signals — this is intentionally a fast heuristic, not a replacement for an actual breach-database check.

## Output shape

```json
{
  "leaks": [{ "source": "phonebook", "emails": ["user@example.com"] }],
  "dark_web": [{ "source": "pattern-match", "confidence": "low", "breach": "..." }],
  "credentials": [],
  "email_reputation": [{ "email": "user@example.com", "reputation": "low risk", "risk_score": 15 }],
  "intelx_phonebook": [],
  "unique_emails_found": ["user@example.com"],
  "total_leaks": 1,
  "total_credentials": 0
}
```

Note that `credentials` in the report has emails obfuscated (`@` → `[at]`) before being written out — see [Reports](/docs/reports/).
