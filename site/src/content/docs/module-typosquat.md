---
title: Typosquatting Detection
description: Domain permutation generation, content similarity, and risk scoring.
section: Modules
order: 5
---

Implemented in `farsight/modules/typosquat.py`, class `TyposquatDetector`. Enabled with `--typosquat` (or via `--all`/`--modules typosquat`).

## Candidate generation

Farsight generates typosquat candidates with [`dnstwist`](https://github.com/elceef/dnstwist) if it's installed, or a hand-rolled fallback generator if it isn't (a keyboard-adjacency replacement map, omission, swap, duplication, insertion, and TLD swap - a strict subset of what dnstwist covers).

`--depth` controls which dnstwist fuzzers run:

- **Depth 1**: addition, bitsquatting, homoglyph, hyphenation, insertion, omission, repetition, replacement, subdomain, transposition, vowel-swap
- **Depth 2**: adds common-misspellings and homophones
- **Depth 3**: adds full dictionary-based fuzzing

Higher depth means substantially more candidates - and since every candidate gets DNS-resolved, run time scales with depth roughly as steeply as candidate count does.

## Active-domain check

Every candidate gets DNS-resolved in bulk. Domains that don't resolve on the first pass get a `socket.gethostbyname` fallback attempt, and a random sample of the still-inactive domains is kept for analysis anyway - the reasoning is that a domain registered defensively (parked, no MX, no web server) is still worth reporting, just at lower risk, rather than silently dropped for being "inactive."

## Per-candidate analysis

For each active candidate, Farsight collects:

- **DNS**: A and MX record presence
- **HTTP**: fetches the page (HTTP then HTTPS), extracts the `<title>`, and records content size
- **Content similarity**: scans the fetched HTML for a fixed list of brand keywords and scores `min(100, hits * 15)`. **This keyword list is currently hardcoded** (`sony`, `playstation`, `ps5`, `ps4`, `vaio`, `bravia`, `xperia`, `electronics`) rather than derived from the scan target - it's a real limitation worth knowing about: content similarity will contribute meaningfully to the risk score only when the target is Sony-related, and silently scores 0 for every other domain. Don't read a 0 content-similarity score as "this typosquat doesn't mimic the brand"; for most targets, it simply means the check didn't look for the right words.
- **String similarity**: `rapidfuzz.fuzz.ratio` between the original and candidate domain (falls back to a Levenshtein implementation if rapidfuzz isn't installed)
- **Typo type classification** (`_determine_typo_type`): compares the domain strings directly to classify the permutation as one of `TLD swap`, `Homoglyph` (character replaced with a visually similar one, e.g. `0`→`o`, `1`→`l`/`i`, `3`→`e`), `Character replacement`, `Character swap` (adjacent transposition), `Character omission`, `Character insertion`, `Character duplication`, `Hyphenation`, or `Combination/Other` if none of the pattern checks match

## Risk scoring

The risk score (0–100) is a weighted combination, computed in `_calculate_risk_score`:

```
score  = similarity * 0.5              # string similarity, weighted 50%
score += 15  if the candidate has an MX record
score += 10  if the candidate serves a web page
score += content_similarity * 0.1      # keyword-hit score, weighted 10%
score += 10  if typo_type == "Homoglyph"
score += 8   if typo_type == "TLD swap"
score += 5   if typo_type == "Character replacement"
score  = min(int(score), 100)
```

MX presence is weighted heaviest among the boolean bonuses because an active mail server on a typosquat domain is the strongest single signal of a phishing setup, not just a defensive registration.

## Filtering and output

A candidate is kept in the results if `risk_score >= typosquat_threshold` (config default `80`, though the module's own constructor default if the config key is absent is `60` - see [Configuration](/docs/configuration/)) **or** raw string similarity exceeds `85`, so a very close lookalike domain isn't excluded purely for lacking MX/web activity. Results are sorted by risk score descending.

## Output shape

```json
{
  "typosquats": [
    {
      "domain": "examp1e.com",
      "type": "Character replacement",
      "risk_score": 71,
      "has_dns": true,
      "has_mx": false,
      "similarity": 92
    }
  ],
  "similarity_threshold": 80
}
```

The web UI's Typosquat Watch panel shows the top 12 active candidates by risk score. See the [Web UI Guide](/docs/web-ui/) for what that looks like, and [Reports](/docs/reports/) for how this data appears in the generated report.
