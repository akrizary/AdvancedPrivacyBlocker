# Ghostery-Class Capability Matrix — v2.1.0

This extension implements independent functional equivalents. It does not contain Ghostery branding, private datasets, proprietary heuristics or hosted telemetry infrastructure.

| Capability area | Implementation | Status | Boundary |
|---|---|---:|---|
| Advertisement blocking | Static and remotely refreshed DNR network filters | Implemented | Active static volume depends on Chromium's shared quota |
| Tracker blocking | Dedicated tracking rulesets and remote subscriptions | Implemented | Dataset differs from Ghostery TrackerDB |
| Individual tracker control | Per-site Default / Block / Allow rules | Implemented | Scoped to subresources; nested-frame initiator behavior can vary by Chromium version |
| Cosmetic filtering | Generic/domain-scoped selectors and exceptions | Implemented | Unsupported procedural cosmetics are intentionally dropped |
| Annoyance blocking | Dedicated nuisance rules and page selectors | Implemented | Site-specific breakage remains possible |
| Known malware destinations | URLHaus-derived rules with elevated priority | Implemented | Not a phishing-complete reputation service, file scanner or antivirus |
| Tracker identification | Local company/category catalog and heuristics | Implemented | Curated catalog is smaller than commercial tracker intelligence |
| Per-page tracker report | Blocked/observed tracker aggregation | Implemented | Exact blocked-event diagnostics are strongest when unpacked |
| Tracking-parameter cleaning | Same-site-safe navigation and broader third-party sanitization | Implemented | Encrypted, opaque and server-side identifiers cannot be sanitized |
| Redirect unwrapping | Known search/social click-wrapper cleaning | Implemented | Unknown/proprietary redirect formats may pass |
| GPC | JavaScript signal plus request header where accepted | Implemented | Site compliance depends on law and site behavior |
| DNT | JavaScript signal plus request header where accepted | Implemented | DNT is only a preference signal |
| Header-rule fallback | Retains content signals when `modifyHeaders` fails | Implemented | Does not force remote sites to honor the signal |
| Cookie-consent rejection | Common CMP selectors and multilingual rejection actions | Best effort | Custom, shadow-DOM and adversarial consent walls may evade automation |
| Consent banner hiding | Hide-only fallback mode | Implemented | Hiding is not equivalent to refusal |
| Search-result intelligence | Destination badges on supported search pages | Implemented | Catalog-based, not full reputation scoring |
| SERP redirect protection | Link cleaning and known wrapper removal | Implemented | Search-engine changes can require maintenance |
| Social widget suppression | Page-level cosmetic controls | Implemented | May hide legitimate embedded functionality |
| Sign-in prompt suppression | Common third-party sign-in prompt selectors | Implemented | Site-specific prompts may differ |
| App-banner suppression | Common install/open-in-app selectors | Implemented | Heuristic selectors can require exceptions |
| Shorts/Reels suppression | Optional interface selectors | Implemented | Platform markup changes can reduce coverage |
| Element zapper | Interactive persistent site-scoped selector | Implemented | Root `html`/`body` removal is blocked for safety |
| Per-site trust | One hour, one day or permanent | Implemented | Explicit trust bypasses protection for matching navigation scope |
| Global pause | Timed session allow rules with resume control | Implemented | Intended only for troubleshooting |
| Context-menu control | Trust, resume, Zap and settings actions | Implemented | Available from the extension action context menu |
| Direct custom filters | Supported network and cosmetic syntax editor | Implemented | Not every uBO/AdGuard procedural directive is convertible to MV3 |
| Custom filter subscriptions | HTTP(S) list management, parsing and refresh | Implemented | Sources are privileged inputs; use trusted maintainers only |
| Per-source outage retention | Failed sources retain last working rules | Implemented | A first-time failed source has no prior rules to retain |
| Broad-exception audit | Flags risky allow rules | Implemented | Heuristic warning, not formal proof |
| Configuration portability | Import/export settings, lists, trust, overrides and zaps | Implemented | Imported structures are size/type constrained |
| Static quota adaptation | Runtime allocation using available static-rule count | Implemented | Browser/global extension quota controls final activation |
| Concurrency protection | Serialized settings and protection-state writes | Implemented | External storage edits remain outside transactional control |
| Build provenance | Per-ruleset source, feature, index, rule count and exception ids in `ruleset-metadata.json` | Implemented | Lists are fetched at build time; no byte counts or SHA-256 hashes are recorded, so builds are not bit-reproducible over time |
| Ruleset integrity checking | `npm run validate` re-checks all packaged rules against Chromium DNR constraints | Implemented | Encodes documented constraints; not a substitute for a real browser load |
| CNAME-cloaking unmasking | None on Chromium | Not implemented | Ordinary Chromium extension APIs do not expose required DNS resolution |
| Ghostery heuristic anonymization | Deterministic sanitization only | Not reproduced | Proprietary implementation unavailable |
| Full Ghostery TrackerDB | Smaller local catalog/public lists | Not reproduced | Dataset and license differ |
| WhoTracks.Me contribution | None | Not implemented | No custom tracking telemetry endpoint |
| True User Agent/community breakage service | None | Not reproduced | Requires Ghostery-hosted community/backend infrastructure |
| Firefox/Gecko-specific interception | Chromium MV3 DNR implementation | Not implemented | A separate Firefox build would require different architecture |
| VPN/Tor/system-wide filtering | None | Out of scope | Browser-extension boundary |
