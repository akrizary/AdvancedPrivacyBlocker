// Ruleset integrity check: node test/validate-rules.mjs   (or: npm run validate)
//
// Chromium refuses to load the WHOLE extension if a single static rule is
// invalid ("Could not load manifest"), and it validates with RE2 + strict
// canonicalisation that cannot be reproduced by a syntax check. This script
// encodes those constraints so a bad build fails here instead of in the browser.
import { readFile, access } from "node:fs/promises";

const VALID_RESOURCE_TYPES = new Set([
  "main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object",
  "xmlhttprequest", "ping", "media", "websocket", "webtransport", "webbundle",
  "other", "csp_report"
]);
const MALWARE_PRIORITY = 2000000;
const MAX_DECLARED_RULESETS = 100;

// Security feeds embed operator credentials in malware C2 and phishing URLs
// (api.telegram.org/bot<token>/..., one-time JWT lures). Packaging those trips
// secret scanners and republishes someone else's credentials, so the build drops
// them and this check makes the invariant enforceable in CI.
const CREDENTIAL_PATTERNS = [
  ["telegram bot token", /\/bot\d{6,12}:[A-Za-z0-9_-]{30,}/],
  ["AWS access key id", /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Slack token", /\bxox[abprs]-[0-9A-Za-z-]{10,}/],
  ["GitHub token", /\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b/],
  ["Stripe key", /\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}/],
  ["SendGrid key", /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/]
];

// DNR urlFilter: ASCII only; "||" domain anchor may not be followed by "*";
// "|" is an anchor only at the very start/end, never mid-pattern.
function invalidUrlFilter(value) {
  if (value === undefined) return false;
  if (value === "") return true;
  if (/[^\x00-\x7F]/.test(value)) return true;
  if (value.startsWith("||*")) return true;
  let rest = value;
  if (rest.startsWith("||")) rest = rest.slice(2);
  else if (rest.startsWith("|")) rest = rest.slice(1);
  if (rest.endsWith("|")) rest = rest.slice(0, -1);
  return rest.includes("|");
}

// initiatorDomains / excludedInitiatorDomains must be canonical lowercase hosts.
function invalidDomain(value) {
  return value === "" || /[^a-z0-9.\-]/.test(value) || !/[a-z0-9]/.test(value);
}

const problems = [];
const note = message => problems.push(message);

const manifest = JSON.parse(await readFile("manifest.json", "utf8"));
const resources = manifest.declarative_net_request?.rule_resources || [];

if (!resources.length) note("manifest declares no rule_resources");
if (resources.length > MAX_DECLARED_RULESETS) {
  note(`${resources.length} declared rulesets exceeds Chromium's limit of ${MAX_DECLARED_RULESETS}`);
}

const seenRulesetIds = new Set();
for (const resource of resources) {
  if (seenRulesetIds.has(resource.id)) note(`duplicate ruleset id: ${resource.id}`);
  seenRulesetIds.add(resource.id);
  try { await access(resource.path); }
  catch { note(`missing ruleset file: ${resource.path} (id ${resource.id})`); }
}

// Generated rulesets must agree with ruleset-metadata.json, which the service
// worker uses to decide what to enable within the static-rule quota.
let metadata = [];
try {
  metadata = JSON.parse(await readFile("rules/generated/ruleset-metadata.json", "utf8")).rulesets || [];
} catch {
  note("rules/generated/ruleset-metadata.json is missing or unreadable");
}
const generated = resources.filter(resource => /_static_/.test(resource.id));
const metadataIds = new Set(metadata.map(entry => entry.id));
const generatedIds = new Set(generated.map(resource => resource.id));
for (const id of metadataIds) if (!generatedIds.has(id)) note(`metadata lists ${id} but the manifest does not`);
for (const id of generatedIds) if (!metadataIds.has(id)) note(`manifest lists ${id} but metadata does not`);

for (const feature of ["ads", "tracking", "annoyances", "malware"]) {
  try { await access(`rules/generated/cosmetic-${feature}.json`); }
  catch { note(`missing cosmetic-${feature}.json (background.js fetches it per page)`); }
}

let totalRules = 0;
let malwareRules = 0;

for (const resource of resources) {
  let rules;
  try { rules = JSON.parse(await readFile(resource.path, "utf8")); }
  catch { continue; } // missing file already reported
  if (!Array.isArray(rules)) { note(`${resource.path} is not a JSON array`); continue; }

  const metaEntry = metadata.find(entry => entry.id === resource.id);
  if (metaEntry && metaEntry.count !== rules.length) {
    note(`${resource.id}: metadata count ${metaEntry.count} != actual ${rules.length}`);
  }

  const isMalware = resource.id === "core_malware" || resource.id.startsWith("malware_static_");
  // Rule ids only need to be unique WITHIN a ruleset -- separate static rulesets
  // have independent id spaces (rules/ads.json and rules/malware.json both start
  // at 1, which is valid).
  const ruleIdsInRuleset = new Set();
  for (const rule of rules) {
    totalRules += 1;
    const condition = rule?.condition || {};

    if (typeof rule?.id !== "number" || rule.id < 1) note(`${resource.id}: rule id must be a positive integer`);
    else if (ruleIdsInRuleset.has(rule.id)) note(`${resource.id}: duplicate rule id ${rule.id}`);
    else ruleIdsInRuleset.add(rule.id);

    if (!rule?.action?.type) note(`${resource.id}: rule ${rule?.id} has no action.type`);
    for (const key of Object.keys(rule || {})) {
      if (!["id", "priority", "action", "condition"].includes(key)) {
        note(`${resource.id}: rule ${rule.id} has unexpected key "${key}"`);
      }
    }

    // Omitting urlFilter/regexFilter is legal -- the rule then matches all URLs,
    // which is how header-modifying rules are scoped purely by type/party. Only
    // flag a rule with NO narrowing of any kind, which would match every request.
    const hasNarrowing = condition.urlFilter !== undefined || condition.regexFilter !== undefined
      || condition.domainType !== undefined
      || (condition.resourceTypes && condition.resourceTypes.length)
      || (condition.initiatorDomains && condition.initiatorDomains.length)
      || (condition.requestDomains && condition.requestDomains.length);
    if (!hasNarrowing) note(`${resource.id}: rule ${rule.id} has no narrowing and would match every request`);
    if (invalidUrlFilter(condition.urlFilter)) {
      note(`${resource.id}: rule ${rule.id} has an invalid urlFilter "${condition.urlFilter}"`);
    }
    const pattern = condition.urlFilter || condition.regexFilter || "";
    for (const [label, regex] of CREDENTIAL_PATTERNS) {
      // Report the match location only -- never echo the credential itself.
      if (regex.test(pattern)) note(`${resource.id}: rule ${rule.id} embeds a ${label}; the build must drop it`);
    }
    // Static regexFilter is compiled by RE2, which rejects lookaround and
    // backreferences that JavaScript accepts. The build skips regex entirely.
    if (condition.regexFilter !== undefined) {
      if (/\(\?[=!<]/.test(condition.regexFilter) || /\\[1-9]/.test(condition.regexFilter)) {
        note(`${resource.id}: rule ${rule.id} uses an RE2-incompatible regexFilter`);
      }
    }
    for (const key of ["initiatorDomains", "excludedInitiatorDomains", "requestDomains"]) {
      const list = condition[key];
      if (!list) continue;
      if (!list.length) note(`${resource.id}: rule ${rule.id} has an empty ${key}`);
      for (const domain of list) {
        if (invalidDomain(domain)) note(`${resource.id}: rule ${rule.id} has invalid ${key} "${domain}"`);
      }
    }
    for (const key of ["resourceTypes", "excludedResourceTypes"]) {
      for (const type of condition[key] || []) {
        if (!VALID_RESOURCE_TYPES.has(type)) note(`${resource.id}: rule ${rule.id} has unknown resource type "${type}"`);
      }
    }

    // Security rules must outrank session allowances (allow-images, trust), or
    // enabling a loosening toggle would silently unblock malicious hosts.
    if (isMalware && rule?.action?.type === "block") {
      malwareRules += 1;
      if (rule.priority !== MALWARE_PRIORITY) {
        note(`${resource.id}: malware rule ${rule.id} priority ${rule.priority} != ${MALWARE_PRIORITY}`);
      }
    }
  }
}

console.log(`Checked ${resources.length} rulesets, ${totalRules.toLocaleString()} rules (${malwareRules.toLocaleString()} malware block rules).`);
if (problems.length) {
  const shown = problems.slice(0, 25);
  for (const problem of shown) console.error(`  ${problem}`);
  if (problems.length > shown.length) console.error(`  ...and ${problems.length - shown.length} more`);
  console.error(`\n${problems.length} problem(s) found.`);
  process.exit(1);
}
console.log("Ruleset integrity OK.");
