---
title: CLI Reference
description: Every command and flag Farsight's command line supports.
section: Reference
order: 1
---

Farsight's entry point (`farsight = "farsight.main:run"`) lazily registers two Typer subcommands, `scan` and `web`, plus a `version` command. Registration is lazy specifically so a core-only install (no `[web]` extra) doesn't break — if `farsight/web` can't be imported, `farsight web` simply doesn't appear rather than crashing the whole CLI.

## `farsight scan`

```
farsight scan <domain> [OPTIONS]
```

<div class="cast-player" data-src="/assets/docs/casts/scan-help.cast" data-cols="84" data-rows="30"></div>

| Flag | Default | Description |
|---|---|---|
| `domain` (positional) | required | Target domain to scan |
| `--output`, `-o` | `./report.md` | Output file path. A `.pdf` extension additionally triggers PDF conversion after the Markdown report is written |
| `--depth`, `-d` | `1` | Scan depth, 1–3. Controls wordlist size, which techniques run, port list breadth, dnstwist fuzzer selection, and which paid-tier API calls are attempted — see below |
| `--modules`, `-m` | none | Explicit module list, repeatable or comma-separated: `org`, `recon`, `threat`, `typosquat`, `news`, `attack_surface`. **Replaces** the enabled set entirely rather than adding to it |
| `--all` | `false` | Enable every module |
| `--news` | `false` | Include News Monitoring |
| `--typosquat` | `false` | Include Typosquatting Detection |
| `--threat-intel`, `-t` | `false` | Include Threat Intelligence |
| `--attack-surface`, `-a` | `false` | Include Extended Attack Surface (ASN/netblock/cloud/bucket search) |
| `--verbose`, `-v` | `false` | Print live per-module colorized summaries, plus which API providers are configured |
| `--timeout` | `30` | Global per-request timeout in seconds |
| `--force`, `-f` | `false` | Overwrite the output file if it already exists |
| `--concurrency`, `-c` | `10` | Maximum concurrent requests |

**`org` and `recon` always run, regardless of flags.** They're unconditionally added to the enabled-module set before any flag is evaluated — there's no way to scan without them short of passing `--modules` with neither name in the list. `--modules` is also an override, not an addition: passing `-m threat` runs *only* Threat Intelligence, not Threat Intelligence plus the defaults.

### What `--depth` actually changes

Depth isn't just "more of the same" — it gates specific behavior in each module:

- **Org Discovery**: at depth ≥2, adds SecurityTrails subdomain/org search, Crunchbase acquisition lookup, and expands the acquisition-via-news lookback window
- **Recon**: at depth 1, subdomain discovery is a small built-in wordlist brute force; at depth ≥2 it switches to combining crt.sh, DNS brute force, permutation scanning, and public APIs (HackerTarget, ThreatCrowd, BufferOver, AlienVault OTX, URLScan.io, optional VirusTotal). Shodan/Censys host queries only run at depth ≥2/3
- **Extended Attack Surface**: the free, keyless ASN/netblock/cloud-tagging pass runs at any depth; keyed provider searches (Shodan, GrayHatWarfare, FullHunt, Netlas, ZoomEye, Onyphe) only run at depth ≥2
- **Threat Intelligence**: IntelX's `documents` bucket search only runs at depth 3
- **Typosquatting Detection**: depth 1 uses dnstwist's core fuzzers (addition, bitsquatting, homoglyph, hyphenation, insertion, omission, repetition, replacement, subdomain, transposition, vowel-swap); depth 2 adds common-misspellings and homophones; depth 3 adds full dictionary-based fuzzing

Higher depth means more requests, more candidates to resolve, and a longer run — depth 3 with `--all` against a domain with many subdomains can take several minutes, mostly spent on DNS resolution for typosquat candidates.

### Examples

```bash
# Basic scan (org discovery + recon only)
farsight scan example.com

# Everything, verbose, showing which API keys are configured
farsight scan example.com --all --verbose

# Just two specific modules, PDF output
farsight scan example.com -m org -m threat --output report.pdf

# Extended attack surface discovery only (plus the always-on org/recon)
farsight scan example.com --attack-surface --verbose

# Deep scan with a longer timeout for slow networks
farsight scan example.com --all --depth 3 --timeout 60
```

Running from source instead of a pip install? Swap `farsight` for `python -m farsight` in any command above.

## `farsight web`

```
farsight web [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Farsight warns if you bind to anything non-loopback, since the web UI has **no authentication** |
| `--port`, `-p` | `8000` | Bind port |
| `--open-browser` / `--no-browser` | open | Auto-open the UI in a browser on startup |
| `--demo` | `false` | Offline replay mode: streams a pre-captured scan through the same event sequence as a live scan, with zero network calls. Useful when a venue network can't be trusted for a live demo |
| `--fixture` | bundled `example.com` fixture | Path to a captured demo fixture JSON. Capture your own with `scripts/capture_demo_fixture.py <domain>` |

```bash
# Live web UI on the default port
farsight web

# Offline demo, no network calls, custom port
farsight web --demo --port 8080

# Bind non-default host/port (still loopback)
farsight web --host 127.0.0.1 --port 9000 --no-browser
```

<div class="cast-player" data-src="/assets/docs/casts/web-startup.cast" data-cols="84" data-rows="12"></div>

See the [Web UI Guide](/docs/web-ui/) for what the interface actually shows once it's running.

## `farsight version`

Prints the installed version (`FARSIGHT v{version}`) and exits. Useful for confirming which release a bug report or these docs correspond to.
