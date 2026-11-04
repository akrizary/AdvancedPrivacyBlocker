# Changelog

## 2.3.0 — ClickFix guard, CNAME uncloaking and filter-compilation fixes

### Added

- **ClickFix / fake-CAPTCHA guard** (`clickfix-guard.js`, MAIN world, default on).
  ClickFix is the most common browser-delivered initial-access technique in 2026
  (47% of attacks in Microsoft's Digital Defense Report; 52% of Push Security's
  Q2 2026 detections), and roughly four in five payloads arrive via search,
  malvertising or SEO poisoning. A page imitates a Turnstile/reCAPTCHA check,
  writes an OS command to the clipboard, and tells the user to paste it into
  Win+R or Terminal — so the user executes it and no network rule ever sees the
  payload. The guard wraps all four clipboard write paths
  (`clipboard.writeText`, `clipboard.write`, a hijacking `copy` listener, and
  `execCommand("copy")`), classifies the text against four token groups
  (interpreters/LOLBins, download-and-execute, stealth flags, CAPTCHA lure
  wrappers). Detects the 2026 DNS-staged (`nslookup -q=txt`) and base64
  `-EncodedCommand` variants.

  Token counts alone cannot separate an installer from a payload — `irm
  get.scoop.sh | iex` is legitimate and scores `downloadExec: 3` — so the policy
  leans on the two signals an honest install snippet never produces, plus
  provenance. A command-shaped payload is **blocked** when it carries a
  CAPTCHA/verification wrapper, when it carries hidden-execution flags
  (`-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass`), or when no click
  preceded it (a real copy button always runs inside its own click handler).
  Anything else command-shaped is allowed through with a banner, so ambiguous
  developer one-liners keep working. `fromCopyControl` is logged but deliberately
  does **not** downgrade a verdict: an attacker can label a fake CAPTCHA button
  "Copy", and treating that as proof of innocence would hand them the bypass.
  The asymmetry is what justifies blocking at all — a wrong block leaves the
  clipboard untouched and the user can still select and copy by hand, while a
  wrong allow ends in code execution.

  The banner has separate wording per verdict: after a block it states that the
  clipboard is unchanged and offers the manual-copy fallback, rather than
  claiming a copy happened. Text that matches a lure token but contains no
  command — Cloudflare's "Ray ID", which error pages legitimately offer to copy
  for support tickets — is allowed silently and raises no banner.
- **CNAME-cloaked tracker uncloaking**, as far as Chromium permits. Chromium
  extensions cannot resolve DNS — which is why uBlock Origin's uncloaking is
  Firefox-only — so the build now packages AdGuard's observed-cloaked-hostname
  list instead. The raw list is ~303,000 rules and would exhaust Chromium's
  ~330,000 shared static quota by itself; most of it is subdomains of the
  trackers' own domains (26,330 under `tt.omtrdc.net` alone) that EasyPrivacy
  and AdGuard Tracking already block. Filtering it against the rules compiled in
  the same run, then collapsing hosts covered by a listed parent, leaves ~8,500
  genuinely invisible cases: cloaked subdomains of first-party sites. These lead
  the tracking group, because `syncStaticRulesets()` enables rulesets by
  round-robin over ascending index and tail rulesets never activate.
  `CAPABILITY_MATRIX.md` is updated from "Not implemented" to "Partial".
- Modern DNR resource types in the privacy header rules: `webtransport`,
  `webbundle` and `csp_report`. Each is a live beacon/exfiltration channel that
  a rule limited to `xmlhttprequest`/`websocket` never matched.
  `test/validate-rules.mjs` already accepted them; no rule had used them.
- 38 campaign/click parameters added to the navigation strip list, including
  `srsltid` (Google Shopping), `_gl` (GA cross-domain linker), Matomo `mtm_*`,
  Piwik `pk_*`, `rdt_cid`, `vgo_ee` and the major affiliate networks; 12 more
  short or routing-ambiguous names added to the third-party-only list.
- `test/hardening.test.mjs`: 61 checks covering filter-option handling, the CNAME
  reduction, the ClickFix classifier against six real payload shapes and eight
  benign strings, every branch of the warn/block policy, and the per-verdict
  banner wording. The ClickFix tests load the shipped guard in a `node:vm`
  sandbox and call its real `describe`/`decide`, so they cannot drift from the
  patterns and thresholds that actually ship.

### Fixed

- **373 packaged rules were silently over-blocking.** `build-rules.mjs` listed
  `$redirect`, `$redirect-rule`, `$removeparam` and `$csp` as known options and
  then ignored them, compiling each into a plain block. `$redirect=noopjs` means
  "swap this script for a harmless stub so the page keeps working", so a hard
  block breaks the page instead; `$redirect-rule` applies only when the request
  would *already* be blocked, so making it unconditional is a different rule
  altogether. `lib/converter.js` already dropped these at runtime — the packaged
  baseline and the live layer now agree.
- **`$elemhide`, `$generichide` and `$genericblock` exceptions became network
  `allow` rules**, which would unblock *every* request to the host rather than
  scoping cosmetic filtering. That weakened protection; they are now dropped.

### Removed

- The `pup-adware` subscription and its build entry. The feed still answers
  HTTP 200 — so no refresh ever reported a failure — but its own header has read
  "Daily update has been paused" since **2023-05-14** and it serves 189 stale
  rules. Stale security data presented as live protection is worse than none.
  HaGeZi Threat Intelligence covers the same ground and stays available as the
  existing opt-in subscription; it is deliberately *not* baked into the static
  build, because at 318,579 rules it would consume the whole static budget.

### Notes

- Added `popup-ads` (HaGeZi Pop-Up Ads) as an **opt-in** subscription. At 77,681
  rules it would crowd out EasyList/EasyPrivacy in the ~29,000-rule dynamic cap.
- The packaged static baseline is now 772,070 rules across 84 rulesets, up from
  455,245. Almost all of that growth is upstream feed growth since the previous
  build, not new sources: AdGuard Tracking alone now yields 407,166 rules. The
  static budget remains heavily oversubscribed by design — rulesets ship
  disabled and the service worker enables what fits Chromium's shared quota.

## 2.2.0 — Popunder protection, security coverage, loosening controls and build rewrite

### Added

- **Popup guard** (`popup-guard.js`, MAIN world): wraps `window.open` so a site's
  document-wide click listener cannot open an unrelated ad tab when you click a
  button. Same-site targets, targets matching a link the user just clicked, known
  sign-in/payment providers and `about:blank` print flows remain allowed; other
  cross-site opens receive a window-like stub. Default on, with one switch to
  disable if a legitimate popup is ever refused.
- **Automatic redirect logging**: blocked popunders and unexplained cross-site
  navigations are recorded to a local, capped, deduplicated log with repeat
  counts, reviewable under *Redirect & popup activity* with a one-click
  **Block domain** action. Intermittent hijacks no longer need to be reproduced
  with DevTools open. Same-tab hijacks are recorded but cannot be intercepted,
  because `window.location` is unforgeable.
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
