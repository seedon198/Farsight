# FARSIGHT — DEF CON 34 / AppSec Village Demo Runbook

This runbook is the exact sequence to run live on stage. It exists so the demo
does not depend on memory or improvisation.

## 1. Before you leave for the venue

Run this once, on the machine you'll actually present from, on the actual
venue Wi-Fi if you can get on it early (crt.sh, GNews, and DNS lookups all
need outbound internet — venue networks sometimes block or rate-limit this).

```bash
git clone https://github.com/seedon198/Farsight.git
cd Farsight
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m farsight --help          # must print the usage screen, not a traceback
python -m farsight version         # must print "FARSIGHT v0.1.0"
```

If `--help` throws a traceback, you're on an old clone that still pulls in
`weasyprint` — re-clone, don't debug on stage.

Then do one full dry run against your chosen target **before the talk** (see
§3) and keep the generated report open in a tab as a fallback in case venue
Wi-Fi dies mid-demo.

## 2. Choosing a target domain

Farsight does WHOIS/DNS/certificate-transparency lookups (passive, no
authorization needed for public data) **and** a port scan of discovered
hosts (active). Scan a domain you own or are explicitly authorized to test —
your own project/company domain is the safest choice for a live audience.
Do not scan a third party's domain on stage without their sign-off.

Substitute your chosen domain for `<TARGET>` everywhere below.

## 3. The live sequence

### Step 1 — fast core demo (~30–45s)

Shows WHOIS, related domains, subdomains, open ports, and threat-intel in
one screen — this is the "wow, it's fast" moment.

```bash
python -m farsight scan <TARGET> -m org -m recon -m threat --verbose
```

### Step 2 — typosquat detection (run this, then talk over it)

This module generates ~2,000 permutations of the target and resolves each
one — it takes **~2 minutes**, the slowest part of the tool by far. Don't run
it live and wait silently. Either:

- Kick it off, then narrate the permutation algorithm (character insertion/
  omission/substitution, homograph tricks) while it runs in the background, or
- Show the **pre-generated** report from your dry run instead of running it live.

```bash
python -m farsight scan <TARGET> -m typosquat --verbose
```

### Step 3 — news monitoring (~5–10s)

```bash
python -m farsight scan <TARGET> -m news --verbose
```

### Optional — everything in one shot (~2.5–3 min total)

Only do this if your slot has room for an uninterrupted 3-minute run; the
fast/typosquat split above is the safer default for a timed talk.

```bash
python -m farsight scan <TARGET> --all --depth 1 --verbose -o report.md
```

### Optional — PDF export

Demonstrates the reporting pipeline end-to-end.

```bash
python -m farsight scan <TARGET> -m org -o report.pdf
```

## 4. Noise you'll see that is expected, not a bug

- Red `ERROR` lines like `Error resolving A record for <random>.com: ... SERVFAIL`
  during the typosquat module — these are DNS lookups for permutations that
  don't exist. They're supposed to fail; that's how the tool tells "squatted"
  domains from "never registered" ones.
- `crt.sh returned status 404` or similar — crt.sh (a free public certificate-
  transparency service) is occasionally slow or rate-limited. It's outside
  Farsight's control; if it happens on stage, mention it and move on — the
  rest of the scan is unaffected.

## 5. Fallback plan

Keep a report generated ahead of time (`report.md` and `report.pdf` from your
pre-venue dry run in §1) open in a browser tab / PDF viewer. If Wi-Fi dies
mid-talk, narrate over the pre-generated report instead of the live terminal.
