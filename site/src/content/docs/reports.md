---
title: Reports
description: What a generated Markdown or PDF report contains.
section: Reference
order: 4
---

Every scan — CLI or web UI — ends at `farsight/modules/report_writer.py`'s `ReportWriter.generate_report()`. Markdown is always written; passing a `.pdf` output path (CLI) or clicking "Download PDF" (web UI, if available) additionally converts it via `convert_to_pdf()`.

## Report structure

Sections are included only for modules that actually ran:

1. **Header** — target domain, scan date, depth, and which modules ran
2. **Executive Summary** — domain/subdomain counts, open port count, email security posture, and a bullet list of notable findings (leaks, phonebook hits, typosquats) pulled to the top so a reader doesn't have to dig for them
3. **Organization & Domain Discovery** — WHOIS block, related domains, certificate-transparency domains, acquisitions table (org / relationship / domain / source / confidence) — see [Organization Discovery](/docs/module-org-discovery/)
4. **Reconnaissance & Asset Discovery** — DNS records per domain, subdomains list, port-scan summary and per-domain open-port tables, email security status and recommendations — see [Recon & Asset Discovery](/docs/module-recon/)
5. **Extended Attack Surface** — ASNs table, netblocks table (cloud-tagged), cloud-provider exposure counts, exposed buckets table, per-engine result counts — see [Extended Attack Surface](/docs/module-attack-surface/)
6. **Threat Intelligence** — leaks table, dark-web mentions table, exposed credentials table, IntelX phonebook table, email-reputation table — see [Threat Intelligence](/docs/module-threat-intel/)
7. **Typosquatting Analysis** — domain / type / status / risk score / DNS-active table — see [Typosquatting Detection](/docs/module-typosquat/)
8. **News Monitoring** — per-article title, date, snippet, link — see [News Monitoring](/docs/module-news/)
9. **Footer** — generator version and timestamp, informational-purposes disclaimer

## Truncation limits

Long lists are capped in the Markdown output, each with an "...and N more" note rather than silently dropped:

| List | Cap |
|---|---|
| Related domains | 50 |
| Certificate-transparency domains | 20 |
| Acquisitions | 30 |
| Subdomains | 100 |
| ASNs | 30 |
| Netblocks | 50 |
| Exposed buckets | 30 |

Leak/mention/credential "details" fields are additionally truncated to 50 characters each, and pipe characters (`|`) inside them are escaped (`\|`) so they don't break Markdown table formatting. Exposed-credential emails are also obfuscated (`@` → `[at]`) before being written to disk.

## PDF conversion is a simple, literal translation — not full Markdown rendering

Worth knowing if you rely on the PDF output: `convert_to_pdf()` splits the Markdown on header lines (`#+ `) and converts each header to a ReportLab heading style, and everything else — including every table in the report — to plain paragraph text. **This means every table renders in the PDF as its raw Markdown syntax (pipes, dashes, and all) inside a paragraph, not as an actual formatted table.** Lists, code blocks, and other Markdown constructs aren't specially handled either. If you need properly-formatted tables, use the Markdown report directly (or the web UI's in-browser HTML render, which uses a real Markdown-to-HTML converter with table support) rather than the PDF.

## Output location

The CLI defaults to `./report.md` (override with `--output`/`-o`); if no output path is given at all in other contexts, reports are auto-named `reports/<domain>/<domain>_<timestamp>_report.md`. The web UI's report endpoints reuse this exact same writer, so a report generated through the browser is byte-for-byte the same format as one from the CLI.
