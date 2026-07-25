import { domainMatches, normalizeDomain } from "./settings.js";
import { PRIVACY_RULE_ID_START } from "./privacy-rules.js";

export const MAX_TRACKER_OVERRIDE_RULES = 2_000;
export const TRACKER_OVERRIDE_RULE_ID_START = PRIVACY_RULE_ID_START + 10_000;
export const TRACKER_OVERRIDE_RESOURCE_TYPES = Object.freeze([
  "sub_frame", "script", "image", "stylesheet", "object", "xmlhttprequest",
  "ping", "media", "font", "websocket", "other"
]);

export function sanitizeTrackerOverrides(input = {}, maxRules = MAX_TRACKER_OVERRIDE_RULES) {
  const output = {};
  let count = 0;
  for (const [siteRaw, trackerMap] of Object.entries(input || {})) {
    const site = normalizeDomain(siteRaw);
    if (!site || !trackerMap || typeof trackerMap !== "object") continue;
    const cleanMap = {};
    for (const [trackerRaw, status] of Object.entries(trackerMap)) {
      const tracker = normalizeDomain(trackerRaw);
      if (!tracker || !["allow", "block"].includes(status) || count >= maxRules) continue;
      cleanMap[tracker] = status;
      count += 1;
    }
    if (Object.keys(cleanMap).length) output[site] = cleanMap;
    if (count >= maxRules) break;
  }
  return output;
}

export function getSiteTrackerOverrides(input, host) {
  const normalizedHost = normalizeDomain(host);
  if (!normalizedHost) return {};
  const clean = sanitizeTrackerOverrides(input);
  const merged = {};
  const matchingSites = Object.keys(clean)
    .filter(site => domainMatches(normalizedHost, site))
    .sort((a, b) => a.length - b.length);
  for (const site of matchingSites) Object.assign(merged, clean[site]);
  return merged;
}

export function buildTrackerOverrideRules(input) {
  const clean = sanitizeTrackerOverrides(input);
  const rules = [];
  let id = TRACKER_OVERRIDE_RULE_ID_START;
  for (const [site, trackerMap] of Object.entries(clean)) {
    for (const [tracker, status] of Object.entries(trackerMap)) {
      rules.push({
        id: id++,
        priority: 1_000,
        action: { type: status },
        condition: {
          requestDomains: [tracker],
          initiatorDomains: [site],
          resourceTypes: [...TRACKER_OVERRIDE_RESOURCE_TYPES]
        }
      });
    }
  }
  return rules;
}
