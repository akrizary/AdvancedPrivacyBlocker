# Validation Report — Advanced Privacy Blocker 2.2.0

Generated: 2026-07-25

## Coverage

- `FULL_TEXT_COVERAGE_VERIFIED`: extension source, manifest, UI files, build scripts, metadata and every packaged DNR JSON file were inspected directly or exhaustively parsed.
- `STATIC_VALIDATION_VERIFIED`: syntax checks, JSON parsing, manifest references, ruleset quotas, per-ruleset rule-ID uniqueness, supported action/condition keys, priority invariants and blanket-block negative controls passed.
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

- Advertisement network rules: **65,529** (7 rulesets)
- Tracking network rules: **249,586** (25 rulesets)
- Annoyance network rules: **20,205** (3 rulesets)
- Security network rules: **119,944** (12 rulesets) — malware, phishing,
  malvertising, botnet C2, PUP/adware and spam TLDs
- Additional core seed rules: **108** (58 ads, 25 trackers, 25 malware)

### Cosmetic inventory

- Advertisement selectors: **31,897**
- Tracking selectors: **255**
- Annoyance selectors: **33,631**
- Security selectors: **461**

## Automated test coverage

`npm test` runs two suites, both reproducible offline:

1. **`test/run-tests.mjs`**
   - Converter unit tests (26 assertions): domain anchors, `$` option parsing,
     `$domain=` include/exclude, exception rules, cosmetic extraction, regex
     acceptance and rejection, comment handling, broad-exception auditing, and
     regressions for DNR-invalid `urlFilter` forms (`||*` prefix, mid-pattern
     `|`) and `$`-in-path splitting.
   - Service-worker smoke test: loads `background.js` against a mocked
     `chrome.*` and exercises all 14 message handlers, then asserts that a
     setting written through a handler survives a re-read. This is the check
     that catches runtime breakage syntax checks miss, such as calling an Array
     method on a `Set`.

2. **`test/validate-rules.mjs`** (also `npm run validate`)
   - Every manifest-declared ruleset file exists and parses.
   - Rule ids are unique within each ruleset, and metadata counts match files.
   - Metadata and manifest declare the same generated ruleset ids.
   - `urlFilter` values satisfy Chromium's ASCII and anchor constraints.
   - No RE2-incompatible `regexFilter` (lookaround, backreferences).
   - `initiatorDomains`/`requestDomains` are canonical lowercase hosts.
   - `resourceTypes` values are valid enum members.
   - Only `id`, `priority`, `action` and `condition` keys are present.
   - Security rules carry the `2,000,000` priority invariant.
   - No rule matches every request without narrowing.
   - Declared ruleset count stays within Chromium's limit of 100.

Both run in CI on every push and pull request.

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
