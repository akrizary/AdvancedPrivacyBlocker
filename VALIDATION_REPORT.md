# Validation Report — Advanced Privacy Blocker 2.1.0

Generated: 2026-07-24

## Coverage

- `FULL_TEXT_COVERAGE_VERIFIED`: extension source, manifest, UI files, build scripts, metadata and every packaged DNR JSON file were inspected directly or exhaustively parsed.
- `STATIC_VALIDATION_VERIFIED`: syntax checks, JSON parsing, manifest references, ruleset quotas, source hashes, rule-ID uniqueness, supported action/condition keys, priority invariants and blanket-block negative controls passed.
- `MOCK_RUNTIME_VALIDATION_VERIFIED`: service-worker behavior passed against a mocked Chrome API runtime.
- `BROWSER_RUNTIME_BLOCKED_BY_ENVIRONMENT_POLICY`: installed Chromium is governed by `ExtensionInstallBlocklist: ["*"]` and `URLBlocklist: ["*"]`.
- `BROWSER_RUNTIME_UNVERIFIED`: no claim is made that representative websites were exercised in an unmanaged browser.

## Rule inventory

- Manifest rulesets: **52** (47 generated + 4 seeds + 1 empty `backup`)
- Enabled-by-default seed rulesets: **4**
- Packaged static DNR rules: **455,372**
- Block actions: **449,216**
- Allow actions: **6,155**
- Modify-header actions: **1**
- Unscoped blanket block rules: **0**

Reproduce these counts with `npm run validate` (`test/validate-rules.mjs`).

### Generated feature inventory

- Advertisement network rules: **58,958**
- Tracking network rules: **193,325**
- Annoyance network rules: **8,058**
- Known-malware network rules: **9,435**
- Additional core seed rules: **83**

### Cosmetic inventory

- Advertisement selectors: **23,395**
- Tracking selectors: **233**
- Annoyance selectors: **36,851**
- Malware selectors: **0**

## Automated test coverage

`npm test` passed the following suites:

1. **Smoke and DNR inventory**
   - Manifest V3 and version checks.
   - Static ruleset limits and unique IDs.
   - Filter conversion and blanket-block negative controls.
   - Settings sanitization.
   - Tracker classification.
   - Privacy sanitization structure.
   - Malware-priority invariant.
2. **Content-tool regressions**
   - Same-site functional-parameter preservation.
   - Cross-site parameter stripping.
   - Google and Facebook redirect unwrapping.
   - Unsupported protocol safety.
3. **Tracker-override regressions**
   - Domain/status sanitization.
   - Parent/specific-site merge order.
   - Rule cap and top-level-navigation exclusion.
4. **Mocked service-worker integration**
   - Static ruleset synchronization.
   - Concurrent setting writes.
   - Concurrent tracker override writes.
   - Concurrent trust writes.
   - `modifyHeaders` failure fallback.
   - Custom network and cosmetic rules.
   - Queued custom-filter updates.
   - Last-working remote-rule retention during simulated outage.
5. **Package audit**
   - Every manifest-declared file exists.
   - Every packaged DNR resource parses.
   - Allowed action and condition schema keys only.
   - Metadata counts match actual files.
   - Metadata and manifest declare the same generated ruleset ids.
   - Security rules carry the `2,000,000` priority invariant.
   - Popup/options asset references resolve.
   - No obvious private key or `.env` artifact is packaged.

## Source-list provenance

Source lists are fetched over HTTPS at build time and are not vendored, so this
build records **no source byte counts or SHA-256 hashes**. See
`BUILD_PROVENANCE.md` for what `ruleset-metadata.json` does record and for the
resulting reproducibility limits, and `THIRD_PARTY_NOTICES.md` for the full list
of the 14 upstream sources and their licences.

## Remaining release gates

1. Load unpacked in an unmanaged Chromium 121+ profile.
2. Exercise representative sites for ads, analytics, consent CMPs, search redirects, zapping and timed trust.
3. Use a harmless controlled test URL for malware-rule verification; do not browse live malicious samples.
4. Test breakage-sensitive flows: login, CAPTCHA, embedded video, checkout and SSO.
5. Inspect the service-worker console for DNR, content-script and list-update errors.
6. Complete Chrome Web Store privacy disclosure, permission justification and upstream-license review before public distribution.
