---
title: Recon & Asset Discovery
description: DNS enumeration, subdomain discovery, and port scanning.
section: Modules
order: 2
---

Implemented in `farsight/modules/recon.py`, class `Recon`. Always runs, alongside [Organization Discovery](/docs/module-org-discovery/) — these two are the modules enabled by default with no flags at all.

## DNS enumeration and email security

Every scan resolves `A`, `MX`, `NS`, `TXT`, and `CNAME` records for the target domain, then checks SPF and DMARC configuration (`check_spf_dmarc`) and reports whether the domain's email posture is well-protected, partially protected, or unprotected — this runs regardless of depth.

## Subdomain discovery: depth changes the technique, not just the limit

This is the module where `--depth` has the most dramatic effect on *how* discovery works, not just how much of it happens:

- **Depth 1**: a small built-in wordlist brute force (`enum_subdomains`) — fast, no external calls beyond DNS itself.
- **Depth ≥2**: switches entirely to `discover_subdomains()` (`farsight/utils/subdomain_enum.py`), combining certificate-transparency (crt.sh), DNS brute force, and — at depth ≥2 specifically — HTML scraping and public APIs (HackerTarget, ThreatCrowd, BufferOver, AlienVault OTX, URLScan.io, and VirusTotal if configured). Result cap: 250.
- **Depth 3**: adds permutation-based candidate generation on top of everything at depth 2, and attempts a zone-transfer request (`_try_zone_transfer`) against every nameserver the domain reports — a legitimate, low-cost check (most nameservers correctly refuse it, but misconfigured ones leak their entire zone in one query). Result cap: 500.

## Port scanning: dedup by IP, not by domain

Before scanning, every domain that resolved to an IP gets grouped by its **first resolved A record** — domains sharing an IP (a CDN, load balancer, or shared host) are scanned exactly once, and the single result is fanned back out to every domain that mapped to it (`_port_scan_targets`). This matters for scan time: a target with 200 subdomains behind one load balancer costs one port scan, not 200.

Port scanning itself prefers `masscan` if it's installed and permitted (`MasscanScanner.is_available()`), falling back to a pure-Python async socket scanner (`PortScanner`) if masscan isn't present, or if it fails with a permission error (masscan typically needs `sudo` or `setcap` for raw sockets) — the fallback keeps the module working on a locked-down machine, just slower.

The port list itself also depends on depth:

- **Depth 1**: `default_ports` from config — a 20-port list covering the most common services.
- **Depth ≥2**: re-scans every domain against a fixed 35-port expanded list (21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443, 8888, 9090, 9200, 27017) covering common database, RDP/VNC, and management-plane ports the basic list skips.

## API sources (optional, depth-gated)

- **Depth ≥2**: Shodan host query, if configured
- **Depth ≥3**: Censys host query, if configured

Neither is required — port scanning and subdomain discovery both work fully without any API key.

## Output shape

```json
{
  "target_domain": "example.com",
  "dns_records": { "example.com": { "A": [...], "MX": [...] } },
  "subdomains": ["www.example.com", "mail.example.com"],
  "email_security": { "spf": "...", "dmarc": "...", "status": "well-protected" },
  "port_scan": {
    "total_scanned": 12,
    "domains_with_open_ports": 8,
    "total_open_ports": 34,
    "domain_results": { "example.com": { "open_ports": 3, "ports": [...] } }
  },
  "total_subdomains": 1
}
```

`Recon` also exposes `export_results()` for writing JSON/TXT/CSV directly, independent of the Markdown/PDF report path — useful if you want to pipe results into another tool rather than read the generated report.

Resolved A records from this module's DNS results feed directly into [Extended Attack Surface](/docs/module-attack-surface/)'s cloud-IP tagging as the "known IPs" list, so cloud membership can be checked without a second DNS pass.
