# Changelog

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
