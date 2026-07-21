---
title: News Monitoring
description: Relevance-scored news tracking across multiple sources.
section: Modules
order: 6
---

Implemented in `farsight/modules/news.py`, class `NewsMonitor`. Enabled with `--news` (or `--all`/`--modules news`). Runs last in the pipeline. Its results are also reused by [Organization Discovery](/docs/module-org-discovery/)'s news-based acquisition detection.

## Primary source: GNews

If the `gnews` library is installed (it's a core dependency, so this is the default path), Farsight uses it to search Google News for mentions of the target, run in a thread executor since the library itself is synchronous.

## The fallback is placeholder data - know this before you rely on it

If `gnews` **isn't** available, `_monitor_alternative` generates **synthetic placeholder articles** - this is explicit in the source, not a hidden bug: the code comments read "Placeholder for demonstration" and "In a real implementation, this would use a real news API." It fabricates up to 5 articles from a fixed set of publisher names and title templates (e.g. `"{target} Announces New Security Measures"`, `"{target} Partners with Leading Cybersecurity Firm"`) with random dates within the lookback window. **If you ever see News Monitoring results that look suspiciously generic or formulaic, check whether `gnews` is actually installed** - `pip install gnews` (already a core dependency of `farsight-recon`, so this should only come up in an unusual environment where it failed to install) restores real results. The web UI surfaces this directly: its `gnews_available` health-check field drives a visible warning banner when the fallback is active.

## Relevance scoring

`extract_relevant_articles` filters and ranks articles with a simple additive score, independent of whatever ranking the source (GNews) already applied:

```
score += 5  if the target string appears in the article title
score += 3  if the target string appears in the snippet
score += 2  per substantial word (>3 characters) of the target that
            appears in the title
score += 1  per substantial word that appears in the snippet
```

An article is kept only if its score reaches at least 3 - a snippet-only mention of the exact target string clears that bar on its own, but a single partial-word match in the snippet does not. Kept articles are sorted by this relevance score, and separately, the final result list is sorted newest-first using a multi-format date parser (RFC 2822 with and without timezone, then ISO date, then ISO datetime) before being capped at `news_results_limit` (default 10).

## Output shape

```json
{
  "articles": [
    { "title": "...", "url": "...", "published": "2026-06-01", "publisher": "...", "snippet": "..." }
  ],
  "total_articles": 9
}
```
