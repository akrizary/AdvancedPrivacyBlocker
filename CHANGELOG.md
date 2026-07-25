# Changelog

## Unreleased — security coverage, loosening controls and build rewrite

### Added

- Page-side **scriptlets** (MAIN world, toggleable) that neutralize anti-adblock
  bait properties and right-click/selection blockers, each individually fail-safe.
- **Loosening controls** for sites broken by strict filtering: global
  image/media/font resource-type allowances, plus a per-site "allow images on this
  site only" rule that permits images initiated by that site including its
  third-party image CDN.
- Five security subscriptions — botnet C2, PUP/adware, spam TLDs, Dandelion
  Anti-Malware and phishing/malvertising — plus an opt-in HaGeZi threat-
  intelligence feed. Packaged security rules grew to ~120,000.
- Regional coverage via ABPindo (Indonesian/Malay) and AdGuard Mobile Ads.
- Tracker catalog expanded to roughly 190 company profiles.
- `test/run-tests.mjs`: converter tests plus a service-worker smoke test that
  loads `background.js` against a mocked `chrome.*` and exercises every message
  handler.
- `test/validate-rules.mjs` (`npm run validate`): re-checks all packaged rules
  against Chromium DNR constraints.
- GitHub Actions CI, `LICENSE` (GPL-3.0-or-later) and `.gitignore`/`.gitattributes`.

### Fixed

- `getBuiltinStates()` called `.includes()` on a `Set`, throwing whenever a
  built-in list had no stored state. Adding new built-in lists triggered it, which
  broke `getOptionsState` — leaving the settings page blank — and also broke
  filter-list refreshes through `getActiveLists()`.
- Settings could appear to revert after closing the page: `setFeature` awaited
  heavy sync work (including remote list downloads) before responding, so a tab
  close could tear down the service worker mid-handler. The durable write now
  completes and responds first, with sync work detached and re-triggered by
  `storage.onChanged`.
- Per-site image allowance was scoped `firstParty`, so it never matched the
  third-party image CDNs comic readers actually use.
- Dynamic (subscription) malware rules were boosted to priority 50,000, below
  per-site trust (900,000) and the resource-type allowances (950,000), so
  trusting a site could override a known-malicious host while packaged static
  rules at 2,000,000 still blocked it. Dynamic now matches static.
- Filter converter: rejected DNR-invalid `urlFilter` patterns (`||*` prefixes,
  mid-pattern `|`), skipped RE2-incompatible regexes in the static build, and
  dropped non-canonical `$domain=` values such as TLD wildcards.

### Changed

- `build-rules.mjs` rewritten to emit feature-grouped rulesets, per-feature
  cosmetic files and `ruleset-metadata.json` matching what the service worker
  loads. The previous script produced a layout the extension could not consume.
- Source-list byte counts and SHA-256 hashes are **no longer recorded**; lists are
  fetched at build time rather than read from pinned local files. This supersedes
  the 2.1.0 entry below. See `BUILD_PROVENANCE.md`.
- UI: real toggle switches, hover/focus states, wrapped setting descriptions and
  a right-aligned per-site control.

## 2.1.0 — Tracker controls, resilience and priority hardening

- Added individual per-site tracker Default / Block / Allow controls in the popup and settings page.
- Added direct inline custom network and cosmetic filter editor.
- Added action context-menu commands for one-hour trust, one-day trust, resume, Zap and settings.
- Split high-confidence navigation parameters from broader cross-site/third-party sanitization to reduce functional URL breakage.
- Added per-source remote-list outage retention instead of replacing protection with an empty or partial ruleset.
- Preserved the last working custom rules when new custom-filter parsing fails.
- Added queued reruns when a filter refresh is requested during an active refresh.
- Serialized concurrent writes for settings, trust entries, tracker overrides, built-in list switches, custom filter text and persistent cosmetic rules.
- Elevated known-malware block priority so per-site tracker exceptions cannot override malware protection.
- Added source-list byte counts and SHA-256 provenance to generated metadata.
- Added content-tool, tracker-override, mocked service-worker and full package-audit regression suites.
- Corrected documentation from “malware/phishing” to “known malware destinations.”

## 2.0.0 — Ghostery-class upgrade

- Split ads, tracking, annoyances and malware into independently controlled DNR rulesets.
- Added adaptive static-rule allocation and remote subscription refresh.
- Added tracker company/category intelligence and page reports.
- Added link cleaning, redirect unwrapping and third-party parameter sanitization.
- Added GPC/DNT page signals and request-header rules with fallback.
- Added common CMP rejection/hide automation.
- Added search-result tracker badges and dynamic SERP observation.
- Added distraction controls and persistent per-site element zapping.
- Added timed site trust, global pause and resume.
- Added custom list management, diagnostics, broad-exception audit and configuration portability.
- Added list download timeout/size limits and subscription count limits.
- Added import sanitization and blanket-block negative controls.
