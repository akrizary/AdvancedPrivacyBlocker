# Build provenance

`npm run build` (`build-rules.mjs`) fetches each source list over HTTPS at build
time and converts it to `declarativeNetRequest` rules. Source lists are **not**
vendored in this repository, so a build reflects upstream state at the moment it
ran. Re-running the build after upstream changes will produce different output.

`rules/generated/ruleset-metadata.json` records, for every generated ruleset:

| Field | Meaning |
| --- | --- |
| `id` | Ruleset id — also its manifest entry and filename |
| `feature` | `ads`, `tracking`, `annoyances` or `malware` |
| `source` | Which upstream list(s) contributed the rules in this file |
| `sourceLocation` | `remote-build` — lists were fetched, not read from disk |
| `index` | Position within its feature group, used for activation ordering |
| `count` | Number of rules in the file |
| `allowIds` | Ids of exception (`allow`) rules in the file |

## Output of the current committed build

| Feature | Static rules | Ruleset files | Cosmetic selectors |
| --- | --- | --- | --- |
| ads | 65,529 | 7 | 31,897 |
| tracking | 249,586 | 25 | 255 |
| annoyances | 20,205 | 3 | 33,631 |
| malware | 119,944 | 12 | 461 |
| **total** | **455,264** | **47** | **66,244** |

Plus five hand-maintained manifest entries: `core_ads` (58 rules),
`core_trackers` (25), `core_annoyances` (0), `core_malware` (25) and the empty
`backup` placeholder — **52 declared rulesets**, within Chromium's limit of 100.

All generated rulesets ship `enabled: false`. The service worker enables them at
runtime, malware first, up to the quota reported by
`declarativeNetRequest.getAvailableStaticRuleCount()`.

## Provenance limitations

- The build records **no source byte counts or SHA-256 hashes**. Builds are
  reproducible in method but not bit-identical over time, because the upstream
  lists change continuously. To pin inputs, vendor the source lists and point the
  build at local copies.
- Recording a hash would prove the same bytes were used; it would not
  independently prove upstream authenticity.
- Public redistribution requires a current review of each upstream project's
  license and attribution requirements — see `THIRD_PARTY_NOTICES.md`.
