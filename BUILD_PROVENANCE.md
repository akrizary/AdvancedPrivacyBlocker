# Build Provenance — 2.1.0

The final rules were generated on **2026-07-24** from local, pinned source-list files. The source files themselves are not bundled in the release; their exact byte counts and SHA-256 hashes are recorded below and in `rules/generated/ruleset-metadata.json`.

| Feature | Upstream list | Build input | Bytes | SHA-256 |
|---|---|---|---:|---|
| Ads | EasyList | `/mnt/data/easylist.txt` | 2,178,513 | `fc5d098f03e79e8c156792a6d1cdd2211f63fdeb61e1dc15a269cb362ef82303` |
| Tracking | AdGuard Tracking Protection | `/mnt/data/adguard_tracking.txt` | 6,383,426 | `13591713026e95b13b13e617aa1f22510fa9bacee5d29f727cb28ddf9a580828` |
| Annoyances | AdGuard Annoyances | `/mnt/data/adguard_annoyances.txt` | 4,232,607 | `9412d4b46bd7dc62f9393a75ef7cec2525dc7effa06b9e3bb99f00ba3d3ae998` |
| Known malware | URLHaus Online | `/mnt/data/urlhaus-filter-ag-online.txt` | 864,866 | `546755baa4d7a0c4834b53cd2d95fd041d32bb5548b8d2c4b00e295992a8cb3a` |

## Rebuild command

```bash
ADS_LIST_FILE=/mnt/data/easylist.txt \
TRACKING_LIST_FILE=/mnt/data/adguard_tracking.txt \
ANNOYANCES_LIST_FILE=/mnt/data/adguard_annoyances.txt \
MALWARE_LIST_FILE=/mnt/data/urlhaus-filter-ag-online.txt \
npm run build
```

## Provenance limitations

- A matching hash proves that the same bytes were used; it does not independently prove upstream authenticity.
- Public distribution requires a current review of each upstream project's license and attribution requirements.
- Rebuilding later from live URLs can produce different rules because these lists change continuously.
