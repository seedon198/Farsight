---
title: FAQ & Troubleshooting
description: Common questions and fixes.
section: Help
order: 1
---

## `farsight` reports missing modules right after I installed it (Windows)

You're almost certainly running `python3` instead of `python` inside your activated virtualenv. On Windows, `python3` frequently resolves to the Microsoft Store Python stub rather than your venv's interpreter, even after `pip install` succeeded cleanly against the venv. Activate the venv, then use `python -m farsight ...` (or just the installed `farsight` command) — not `python3`.

## The Extended Attack Surface panel/section is completely empty

This is often correct behavior, not a bug: a target with no BGP-announced infrastructure of its own and no public AWS/Azure/GCP footprint will legitimately produce empty ASN, netblock, and bucket tables. It can also mean the free BGPView API (or its bgp.he.net fallback) was unreachable from your network at scan time — check the verbose CLI output or the web server logs for `BGPView search unavailable` messages. Neither case needs an API key to fix; the keyless discovery path (see [Extended Attack Surface](/docs/module-attack-surface/)) is what's failing to reach the network, not a missing credential.

## News Monitoring results look suspiciously generic or repetitive

Check whether the `gnews` library is actually installed and importable. If it isn't, Farsight silently falls back to **fabricated placeholder articles** (explicitly labeled as such in the source) so the module still returns something — see [News Monitoring](/docs/module-news/). `gnews` is a core dependency, so this should only happen in an unusual environment where its install failed; `pip install gnews` fixes it. The web UI's health endpoint reports `gnews_available` directly, and shows a warning banner when the fallback is active.

## A typosquat/threat-intel scan is taking a very long time

Typosquat detection resolves every generated candidate domain via DNS, and higher `--depth` generates dramatically more candidates (dictionary-based fuzzing kicks in at depth 3). On a network with slow or unreliable DNS resolution, this is the single biggest contributor to scan time — each failed lookup can cost several seconds in retries. If you need a faster scan, drop `--depth` to 1 or omit `--typosquat`/`--all`.

## Port scanning seems slow or limited

Farsight prefers `masscan` if it's installed, but masscan needs elevated privileges (`sudo` or `setcap` on Linux) for raw sockets — if it can't get them, or isn't installed at all, Farsight transparently falls back to a pure-Python async socket scanner, which works everywhere but is slower. This is intentional graceful degradation, not a misconfiguration to fix, unless you specifically want masscan's speed.

## Why doesn't a configured Censys key return certificate search results?

Censys's certificate search endpoint requires a paid/organization API tier — free personal-access-token accounts get a 403. Farsight detects this and skips the call outright (logging why) rather than retrying a request that can never succeed on a free key. Censys *host* search (used in Recon at depth ≥2) is unaffected and works on a free key.

## The web UI rejected my scan with "a scan is already in progress"

The web UI intentionally allows only one concurrent scan (see [Architecture](/docs/architecture/#concurrency-and-safety)) — this isn't a bug, it's because scan-level settings like timeout and concurrency are held in shared, non-concurrency-safe config state. Wait for the running scan to finish (or restart the server) before starting another.

## Can I expose the web UI to my network / a team?

Not safely as-is. It has **no authentication** by design — it's meant for a single presenter on their own machine. Farsight prints a warning if you bind `--host` to anything other than loopback, but the warning doesn't add any actual access control.

## PDF report tables look broken (raw pipe characters and dashes)

This is a known limitation of the PDF conversion path, not a rendering bug in your PDF viewer — see [Reports](/docs/reports/#pdf-conversion-is-a-simple-literal-translation--not-full-markdown-rendering). Use the Markdown report or the web UI's in-browser HTML view if you need properly formatted tables.

## Do I need any API keys to get useful results?

No. WHOIS, certificate transparency, passive DNS, DNS enumeration, subdomain discovery, port scanning, PhoneBook.cz leak checks, Wikidata/news acquisition discovery, dnstwist-based typosquat generation, and the entire keyless side of Extended Attack Surface (ASN/netblock discovery, cloud-IP tagging) all work with zero configuration. API keys unlock *additional* sources layered on top — see [Configuration & API Keys](/docs/configuration/) for exactly what each one adds.

## Where do I report a bug or ask something not covered here?

Open an issue on [GitHub](https://github.com/seedon198/Farsight/issues). For security vulnerabilities specifically, see `.github/SECURITY.md` in the repository rather than filing a public issue.
