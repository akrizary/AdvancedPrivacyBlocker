# Third-party filter data notices

This repository contains filtering rules generated from externally maintained
filter lists. The extension itself is independent from those projects and from
Ghostery.

Rules under `rules/generated/` are produced by `npm run build`, which fetches the
sources below at build time. `rules/generated/ruleset-metadata.json` records which
source produced each generated ruleset.

## Sources compiled into the packaged static rules

| Source | Feature | Location |
| --- | --- | --- |
| EasyList | ads | `https://easylist.to/easylist/easylist.txt` |
| ABPindo (Indonesian / Malay) | ads | `https://github.com/ABPindo/indonesianadblockrules` |
| AdGuard Mobile Ads | ads | `https://filters.adtidy.org/extension/chromium/filters/11.txt` |
| EasyPrivacy | tracking | `https://easylist.to/easylist/easyprivacy.txt` |
| AdGuard Tracking Protection | tracking | `https://filters.adtidy.org/extension/chromium/filters/3.txt` |
| AdGuard Annoyances | annoyances | `https://filters.adtidy.org/extension/chromium/filters/14.txt` |
| URLHaus Online Malware | malware | `https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt` |
| Phishing / Malvertising | malware | `https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt` |
| Botnet C2 | malware | `https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt` |
| PUP / Adware | malware | `https://malware-filter.gitlab.io/pup-filter/pup-filter-ag.txt` |
| Spam TLDs (HaGeZi) | malware | `https://github.com/hagezi/dns-blocklists` |
| Dandelion Sprout Anti-Malware | malware | `https://github.com/DandelionSprout/adfilt` |

## Built-in subscriptions shipped disabled (runtime only)

| Source | Feature |
| --- | --- |
| AdGuard Base | ads |
| HaGeZi Threat Intelligence (`tif.medium`) | malware |

Users may also add arbitrary HTTP(S) filter-list subscriptions at runtime. Those
are fetched by the extension and are not part of this repository.

## Licensing

Each list remains under its own upstream license and attribution terms. Notably
EasyList and the AdGuard filter lists are distributed under the GNU General Public
License v3 (EasyList additionally offers CC BY-SA 3.0). Because this repository
distributes rules derived from those lists, the project is licensed under
**GPL-3.0-or-later** (see `LICENSE`) for license compatibility.

Redistributors should review each current upstream license before publishing a
derived package. This file is a compliance aid, not a legal opinion.
