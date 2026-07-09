# FARSIGHT DEFCON 34 Website — Design Spec

**Date:** 2026-07-09
**Status:** Approved

## Purpose

Build a single-page marketing/informational website for the FARSIGHT project, to be shared ahead of and during its AppSec Village talk at DEFCON 34 (Aug 6–9, 2026, Las Vegas). The site leads with the project itself (features, install/quickstart, demo) and includes a dedicated section for the DEFCON 34 and BlackHat 2025 Arsenal talks, plus a speaker bio. Hosted on GitHub Pages under the custom domain `farsight.click` (DNS managed in Cloudflare).

## Non-goals

- No CMS, no dynamic backend, no multi-page site/blog.
- No automated Cloudflare DNS changes — DNS records are applied manually by the user in the Cloudflare dashboard.
- No changes to the existing Python package (`farsight/`) or its README.

## Architecture & repo layout

A new `site/` directory at the repo root holds a self-contained Astro + Tailwind CSS project, kept separate from the `farsight/` Python package.

```
site/
  package.json
  astro.config.mjs
  tailwind.config.mjs
  public/
    CNAME                  # "farsight.click" — required for GH Pages custom domain on Actions deploys
    assets/                # copied from docs/assets (logo.svg, demo.gif, blackhat-logo.png, appsecvillage-logo.png, speaker photo)
  src/
    layouts/BaseLayout.astro
    components/
      Hero.astro
      InstallBlock.astro       # quickstart commands with copy-to-clipboard button
      FeatureGrid.astro
      DemoSection.astro        # embeds demo.gif in a terminal-window frame
      ConferenceSection.astro  # DEFCON 34 + BlackHat 2025 cards
      SpeakerSection.astro     # speaker bio card
      Footer.astro
    pages/index.astro          # assembles the above into the single page
```

`docs/assets/*` stay where they are (used by the GitHub-rendered README). The site gets its own copies under `site/public/assets` so the two aren't coupled.

## Visual direction

Clean, modern, dark-mode-first security-product look (not a retro terminal pastiche) — refined typography and spacing, dark background with accent colors, monospace used specifically for code/command blocks. Built with Tailwind CSS utility classes.

## Page content (single scrolling page)

1. **Hero** — FARSIGHT logo, tagline ("Turning OSINT into Actionable Attack Surface Intelligence"), one-line description, CTAs (GitHub repo, jump to Install).
2. **Install/Quickstart** — `git clone` / `pip install` / `python -m farsight scan example.com` commands from the README, styled code block with copy button.
3. **Feature grid** — 6 cards: Organization Discovery, Recon & Asset Discovery, Threat Intelligence, Typosquatting Detection, News Monitoring, Reporting.
4. **Live demo** — existing `demo.gif` in a terminal-window-styled frame.
5. **Conference section** — two cards: DEFCON 34 / AppSec Village (Aug 6–9, 2026, Las Vegas, link to Sessionize talk) and BlackHat 2025 Arsenal (Toronto, link to Black Hat schedule page).
6. **Speaker section** — Adlin Seedon D'Souza: photo, title "Hardware Security Enthusiast and Guide," short bio (RF hacking, drone security, exploitation techniques; ex-Sony, currently at Festo), links to Twitter (@seedonD) and LinkedIn (linkedin.com/in/seedon).
7. **Footer** — GitHub stars/CI badges (same as README), license, links to Issues/Contributing.

## Deployment pipeline

- `.github/workflows/deploy-pages.yml`: triggers on push to `main` (paths: `site/**`) and `workflow_dispatch`. Steps: checkout → setup Node → `npm ci` in `site/` → `npm run build` → upload `site/dist` as the Pages artifact → `actions/deploy-pages` deploy step.
- Repo setting (one-time, manual, done by user): Settings → Pages → Source: "GitHub Actions".
- Custom domain: `site/public/CNAME` contains `farsight.click`, included in every build's `dist/` output (required for Actions-based Pages deploys). User also enters `farsight.click` once in Settings → Pages → Custom domain, and enables "Enforce HTTPS" once the certificate issues.

## Cloudflare DNS setup (manual, user-executed)

DNS tab for `farsight.click`, all records set to **DNS only** (grey cloud, proxy off):

| Type | Name | Content |
|------|------|---------|
| A | `@` | `185.199.108.153` |
| A | `@` | `185.199.109.153` |
| A | `@` | `185.199.110.153` |
| A | `@` | `185.199.111.153` |
| CNAME | `www` | `seedon198.github.io` |

Proxy must stay off so GitHub can directly verify DNS and issue the TLS certificate for the custom domain. If proxying is enabled later, Cloudflare SSL/TLS mode must be "Full" (not "Flexible") to avoid redirect loops.

## Testing/QA plan

- CI gate: `npm run build` step in the deploy workflow fails the workflow on any Astro/Tailwind build error.
- Manual QA after first deploy: load `https://farsight.click`, verify all sections render (hero, feature grid, demo gif, conference cards, speaker section), check mobile viewport, verify install copy-button works, verify HTTPS padlock once the certificate issues.
- Accessibility basics: alt text on all images/logos, semantic heading structure, sufficient color contrast in the dark theme.
