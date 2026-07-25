import { parseFilterList } from "./lib/converter.js";
import { DEFAULT_SETTINGS, domainMatches, getSettings, isTrustActive, normalizeDomain, setSettings } from "./lib/settings.js";
import { buildPrivacyRules, FILTER_RULE_ID_MAX, isPrivacyRuleId, SESSION_RULE_ID_START } from "./lib/privacy-rules.js";
import { classifyDestination, classifyRequest, summarizeTrackers } from "./lib/tracker-intelligence.js";
import { buildTrackerOverrideRules, getSiteTrackerOverrides, sanitizeTrackerOverrides } from "./lib/tracker-overrides.js";
import { registrableApprox } from "./lib/domain-utils.js";

const BUILTIN_LISTS = Object.freeze([
  { id: "easylist", name: "EasyList", url: "https://easylist.to/easylist/easylist.txt", feature: "ads", enabled: true },
  { id: "easyprivacy", name: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt", feature: "tracking", enabled: true },
  { id: "adguard-tracking", name: "AdGuard Tracking Protection", url: "https://filters.adtidy.org/extension/chromium/filters/3.txt", feature: "tracking", enabled: true },
  { id: "adguard-annoyances", name: "AdGuard Annoyances", url: "https://filters.adtidy.org/extension/chromium/filters/14.txt", feature: "annoyances", enabled: true },
  { id: "urlhaus-online", name: "URLHaus Online Malware", url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt", feature: "malware", enabled: true },
  { id: "phishing-online", name: "Phishing & Malvertising (malware-filter)", url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt", feature: "malware", enabled: true },
  { id: "botnet-c2", name: "Botnet C2 / malware callbacks", url: "https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt", feature: "malware", enabled: true },
  { id: "pup-adware", name: "PUP & adware destinations", url: "https://malware-filter.gitlab.io/pup-filter/pup-filter-ag.txt", feature: "malware", enabled: true },
  { id: "spam-tlds", name: "Spam TLDs (throwaway ad domains)", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds.txt", feature: "malware", enabled: true },
  { id: "dandelion-antimalware", name: "Dandelion Sprout Anti-Malware", url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt", feature: "malware", enabled: true },
  // Broad threat-intelligence feed (~450k rules, 9 MB). Shipped DISABLED: the
  // dynamic layer interleaves lists into a ~29k cap, so a list this large would
  // crowd out EasyList/EasyPrivacy. Enable it only if you want maximum
  // known-bad-domain coverage and accept a smaller slice for ad/tracker lists.
  { id: "hagezi-tif", name: "HaGeZi Threat Intelligence (heavy, opt-in)", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt", feature: "malware", enabled: false },
  // Regional: ABPindo is the de-facto Indonesian/Malay list -- SEA ad networks and
  // site templates overlap heavily across ID/MY, so it improves local coverage
  // (incl. ~1.4k cosmetic rules for regional ad containers). Both are small, so
  // they barely consume the shared dynamic budget.
  { id: "abpindo", name: "ABPindo (Indonesian / Malay ads)", url: "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt", feature: "ads", enabled: true },
  { id: "adguard-mobile", name: "AdGuard Mobile Ads", url: "https://filters.adtidy.org/extension/chromium/filters/11.txt", feature: "ads", enabled: true },
  { id: "adguard-base", name: "AdGuard Base", url: "https://filters.adtidy.org/extension/chromium/filters/2.txt", feature: "ads", enabled: false }
]);

const MANAGED_SEED_RULESETS = Object.freeze({
  ads: "core_ads",
  tracking: "core_trackers",
  annoyances: "core_annoyances",
  malware: "core_malware"
});
const FEATURE_SETTING = Object.freeze({
  ads: "adBlocking",
  tracking: "antiTracking",
  annoyances: "annoyances",
  malware: "malwareProtection"
});
const STATIC_PRIORITY = Object.freeze(["malware", "tracking", "ads", "annoyances"]);
const SESSION_GLOBAL_PAUSE_ID = SESSION_RULE_ID_START;
const SESSION_TRUST_ID_START = SESSION_RULE_ID_START + 1;
const SESSION_ALLOWANCE_ID = SESSION_RULE_ID_START + 1000;
const SESSION_IMAGE_ALLOW_START = SESSION_RULE_ID_START + 2000;
const DYNAMIC_FILTER_CAP = FILTER_RULE_ID_MAX;
const MAX_STATIC_RULESETS_ENABLED = 50;
const MAX_COSMETIC_PER_PAGE = 5000;
const MAX_CUSTOM_LISTS = 50;
const MAX_REMOTE_LIST_BYTES = 25 * 1024 * 1024;
const MAX_INLINE_FILTER_BYTES = 1 * 1024 * 1024;
const MAX_INLINE_NETWORK_RULES = 5_000;
// Security blocks must outrank session allowances (global pause 1,000,000,
// resource-type allowances 950,000, per-site trust 900,000) so that trusting a
// site or enabling "allow images" cannot unblock a known-malicious host. This
// matches MALWARE_BLOCK_PRIORITY in build-rules.mjs, which stamps the packaged
// static security rules -- the two must stay in sync.
const MALWARE_BLOCK_PRIORITY = 2_000_000;
const REMOTE_FETCH_TIMEOUT_MS = 30_000;
const VALID_LIST_FEATURES = new Set(["ads", "tracking", "annoyances", "malware", "custom"]);

let refreshInFlight = null;
let refreshAgain = false;
let packagedCosmeticCache = null;
let staticMetadataCache = null;
let dynamicRuleMetaCache = null;
let cosmeticHostCache = new Map();
let staticSyncQueue = Promise.resolve();
let privacySyncQueue = Promise.resolve();
let privacyScriptSyncQueue = Promise.resolve();
let scriptletSyncQueue = Promise.resolve();
let popupGuardSyncQueue = Promise.resolve();
let trustSyncQueue = Promise.resolve();
let statsWriteQueue = Promise.resolve();
let trustMutationQueue = Promise.resolve();
let trackerOverrideMutationQueue = Promise.resolve();
let customFilterMutationQueue = Promise.resolve();
let builtinStateMutationQueue = Promise.resolve();
let cosmeticMutationQueue = Promise.resolve();
const trackerWriteQueues = new Map();

// --- redirect / popunder capture ---------------------------------------------
// Click-hijacks are intermittent, so they are recorded persistently instead of
// requiring the user to watch DevTools. Kept local; never uploaded.
const MAX_REDIRECT_EVENTS = 300;
const ANCHOR_CLICK_GRACE_MS = 2500;
const recentAnchorClicks = new Map(); // tabId -> { host, at }
const lastTabUrls = new Map();        // tabId -> last known top-level URL
let redirectEventQueue = Promise.resolve();

function logRedirectEvent(entry) {
  redirectEventQueue = redirectEventQueue.catch(() => {}).then(async () => {
    const { redirectEvents = [] } = await chrome.storage.local.get("redirectEvents");
    const list = Array.isArray(redirectEvents) ? redirectEvents : [];
    // Collapse repeats of the same destination on the same page into a count.
    const existing = list.find(item => item.kind === entry.kind && item.to === entry.to && item.fromHost === entry.fromHost);
    if (existing) {
      existing.count = Number(existing.count || 1) + 1;
      existing.at = entry.at;
    } else {
      list.unshift({ ...entry, count: 1 });
    }
    await chrome.storage.local.set({ redirectEvents: list.slice(0, MAX_REDIRECT_EVENTS) });
  });
  return redirectEventQueue;
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function featureEnabled(settings, feature) {
  return Boolean(settings[FEATURE_SETTING[feature]]);
}

function sessionKey(tabId) { return `tabReport:${tabId}`; }
function contentCounterKey(tabId) { return `contentCounters:${tabId}`; }

async function getBuiltinStates() {
  const { builtinStates = {}, disabledBuiltin = [] } = await chrome.storage.local.get(["builtinStates", "disabledBuiltin"]);
  const legacyDisabled = new Set(disabledBuiltin || []);
  const result = {};
  for (const item of BUILTIN_LISTS) {
    if (Object.prototype.hasOwnProperty.call(builtinStates, item.id)) result[item.id] = Boolean(builtinStates[item.id]);
    // legacyDisabled is a Set -- must use .has(), not .includes(). This branch is
    // only reached for built-in lists that have no stored state yet (i.e. newly
    // added ones), which is why the bug stayed latent until new lists shipped.
    else if (legacyDisabled.has(item.url)) result[item.id] = false;
    else result[item.id] = item.enabled;
  }
  return result;
}

async function getActiveLists() {
  const [settings, states, stored] = await Promise.all([
    getSettings(),
    getBuiltinStates(),
    chrome.storage.local.get("customLists")
  ]);
  const builtins = BUILTIN_LISTS
    .filter(item => states[item.id] && featureEnabled(settings, item.feature))
    .map(item => ({ ...item, builtin: true }));
  const customs = (stored.customLists || [])
    .slice(0, MAX_CUSTOM_LISTS)
    .filter(item => item?.enabled && /^https?:\/\//i.test(item.url || ""))
    .map((item, index) => ({
      id: item.id || `custom-${index}`,
      name: String(item.name || item.url).slice(0, 200),
      url: item.url,
      feature: VALID_LIST_FEATURES.has(item.feature) ? item.feature : "tracking",
      builtin: false
    }))
    .filter(item => featureEnabled(settings, item.feature) || item.feature === "custom");
  return [...builtins, ...customs];
}

async function fetchRemoteList(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REMOTE_FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      cache: "no-cache", credentials: "omit", redirect: "follow", signal: controller.signal
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const declared = Number(response.headers.get("content-length") || 0);
    if (declared > MAX_REMOTE_LIST_BYTES) throw new Error(`List exceeds ${MAX_REMOTE_LIST_BYTES} bytes`);
    const text = await response.text();
    if (new Blob([text]).size > MAX_REMOTE_LIST_BYTES) throw new Error(`List exceeds ${MAX_REMOTE_LIST_BYTES} bytes`);
    return text;
  } finally {
    clearTimeout(timer);
  }
}

async function parseInlineFilters() {
  const { customFilterText = "" } = await chrome.storage.local.get("customFilterText");
  const text = String(customFilterText || "");
  if (!text.trim()) return null;
  if (new TextEncoder().encode(text).length > MAX_INLINE_FILTER_BYTES) {
    throw new Error(`Custom filters exceed ${MAX_INLINE_FILTER_BYTES} bytes`);
  }
  const parsed = await parseFilterList(text, 1);
  return {
    id: "inline-custom",
    name: "My custom filters",
    url: "local://custom-filters",
    feature: "custom",
    builtin: false,
    local: true,
    network: parsed.network,
    cosmetic: parsed.cosmetic,
    flaggedExceptions: parsed.flaggedExceptions,
    stat: {
      id: "inline-custom", name: "My custom filters", url: "local://custom-filters", feature: "custom",
      ok: true, rules: parsed.network.length, blocks: parsed.blockCount, exceptions: parsed.exceptionCount,
      regex: parsed.regexCount, cosmetic: parsed.cosmetic.length, flagged: parsed.flaggedExceptions.length, error: ""
    }
  };
}

function interleaveBuckets(entries, cap) {
  const buckets = entries.map(entry => ({ ...entry, index: 0 }));
  const result = [];
  while (result.length < cap) {
    let added = false;
    for (const bucket of buckets) {
      if (bucket.index >= bucket.network.length) continue;
      result.push({ rule: bucket.network[bucket.index++], feature: bucket.feature, source: bucket.url });
      added = true;
      if (result.length >= cap) break;
    }
    if (!added) break;
  }
  return result;
}

function materializeDynamicRules(selected) {
  return selected.map((entry, index) => ({
    id: index + 1,
    priority: entry.feature === "malware" && entry.rule.action?.type === "block"
      ? Math.max(MALWARE_BLOCK_PRIORITY, Number(entry.rule.priority || 1))
      : Number(entry.rule.priority || 1),
    action: entry.rule.action,
    condition: entry.rule.condition
  }));
}

async function refreshFiltersOnce() {
  try {
    const lists = await getActiveLists();
    const parsedRemoteLists = [];
    const failedRemoteLists = [];
    const perListStats = [];
    const flaggedExceptions = [];
    const freshCosmetic = [];
    let inline = null;
    let inlineParseFailed = false;

    try {
      inline = await parseInlineFilters();
      if (inline) {
        perListStats.push(inline.stat);
        for (const rule of inline.cosmetic) freshCosmetic.push({ ...rule, feature: "custom", source: inline.id });
        for (const issue of inline.flaggedExceptions) flaggedExceptions.push({ ...issue, source: inline.name });
      }
    } catch (error) {
      inlineParseFailed = true;
      perListStats.push({
        id: "inline-custom", name: "My custom filters", url: "local://custom-filters", feature: "custom",
        ok: false, rules: 0, blocks: 0, exceptions: 0, regex: 0, cosmetic: 0, flagged: 0,
        error: String(error?.message || error)
      });
    }

    for (const item of lists) {
      const stat = {
        id: item.id, name: item.name, url: item.url, feature: item.feature,
        ok: false, rules: 0, blocks: 0, exceptions: 0, regex: 0, cosmetic: 0,
        flagged: 0, error: ""
      };
      try {
        const text = await fetchRemoteList(item.url);
        const parsed = await parseFilterList(text, 1);
        stat.ok = true;
        stat.rules = parsed.network.length;
        stat.blocks = parsed.blockCount;
        stat.exceptions = parsed.exceptionCount;
        stat.regex = parsed.regexCount;
        stat.cosmetic = parsed.cosmetic.length;
        stat.flagged = parsed.flaggedExceptions.length;
        parsedRemoteLists.push({ ...item, network: parsed.network });
        for (const rule of parsed.cosmetic) freshCosmetic.push({ ...rule, feature: item.feature, source: item.id });
        for (const issue of parsed.flaggedExceptions) flaggedExceptions.push({ ...issue, source: item.name });
      } catch (error) {
        stat.error = String(error?.message || error);
        failedRemoteLists.push(item);
        console.warn("Filter fetch failed:", item.url, error);
      }
      perListStats.push(stat);
    }

    const [existingRules, storedExisting] = await Promise.all([
      chrome.declarativeNetRequest.getDynamicRules(),
      chrome.storage.local.get(["dynamicRuleMeta", "dynamicCosmetic", "lastUpdate"])
    ]);
    const existingFilterRules = existingRules.filter(rule => rule.id <= FILTER_RULE_ID_MAX);
    const existingMeta = Array.isArray(storedExisting.dynamicRuleMeta) ? storedExisting.dynamicRuleMeta : [];
    const failedByUrl = new Map(failedRemoteLists.map(item => [item.url, item]));
    const retainedBuckets = new Map();
    let retainedInlineNetwork = [];

    for (const rule of existingFilterRules) {
      const meta = existingMeta[Number(rule.id) - 1] || {};
      const entryRule = { priority: rule.priority, action: rule.action, condition: rule.condition };
      if (inlineParseFailed && meta.source === "local://custom-filters") {
        retainedInlineNetwork.push(entryRule);
        continue;
      }
      const failed = failedByUrl.get(meta.source);
      if (!failed) continue;
      if (!retainedBuckets.has(meta.source)) retainedBuckets.set(meta.source, { ...failed, network: [] });
      retainedBuckets.get(meta.source).network.push(entryRule);
    }

    const inlineSelected = inline
      ? inline.network.slice(0, MAX_INLINE_NETWORK_RULES).map(rule => ({ rule, feature: "custom", source: inline.url }))
      : inlineParseFailed
        ? retainedInlineNetwork.slice(0, MAX_INLINE_NETWORK_RULES).map(rule => ({ rule, feature: "custom", source: "local://custom-filters" }))
        : [];
    const remoteBuckets = [...parsedRemoteLists, ...retainedBuckets.values()];
    const remoteSelected = interleaveBuckets(remoteBuckets, Math.max(0, DYNAMIC_FILTER_CAP - inlineSelected.length));
    const selected = [...inlineSelected, ...remoteSelected];
    const finalRules = materializeDynamicRules(selected);
    const finalMeta = selected.map(entry => ({
      feature: entry.feature,
      action: entry.rule.action.type,
      source: entry.source
    }));

    const failedIds = new Set(failedRemoteLists.map(item => item.id));
    const retainedCosmetic = (storedExisting.dynamicCosmetic || []).filter(rule =>
      failedIds.has(rule.source) || (inlineParseFailed && rule.source === "inline-custom")
    );
    const finalCosmetic = [...freshCosmetic, ...retainedCosmetic].slice(0, 70_000);

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingFilterRules.map(rule => rule.id),
      addRules: finalRules
    });

    dynamicRuleMetaCache = finalMeta;
    cosmeticHostCache.clear();
    const partialFailure = failedRemoteLists.length > 0 || inlineParseFailed;
    const allRemoteFailed = lists.length > 0 && failedRemoteLists.length === lists.length;
    const now = Date.now();
    const updateError = [
      failedRemoteLists.length ? `${failedRemoteLists.length} remote list(s) failed; last working rules were retained where available.` : "",
      inlineParseFailed ? "Custom filter parsing failed; the last working custom rules were retained." : ""
    ].filter(Boolean).join(" ");
    const storagePatch = {
      dynamicCosmetic: finalCosmetic,
      dynamicRuleMeta: finalMeta,
      lastUpdateAttempt: now,
      lastUpdateError: updateError,
      ruleCount: finalRules.length,
      totalParsed: (inline?.network.length || retainedInlineNetwork.length || 0)
        + parsedRemoteLists.reduce((sum, item) => sum + item.network.length, 0),
      perListStats,
      flaggedExceptions: flaggedExceptions.slice(0, 1000)
    };
    if (!partialFailure) storagePatch.lastUpdate = now;
    else if (!storedExisting.lastUpdate && parsedRemoteLists.length) storagePatch.lastUpdate = now;
    await chrome.storage.local.set(storagePatch);

    return {
      ok: !allRemoteFailed && !inlineParseFailed,
      partial: partialFailure,
      retained: partialFailure,
      rules: finalRules.length,
      failedRemoteLists: failedRemoteLists.map(item => item.id),
      perListStats
    };
  } catch (error) {
    console.error("refreshFilters failed", error);
    await chrome.storage.local.set({ lastUpdateAttempt: Date.now(), lastUpdateError: String(error) });
    return { ok: false, error: String(error) };
  }
}

async function refreshFilters() {
  if (refreshInFlight) {
    refreshAgain = true;
    return refreshInFlight;
  }
  refreshInFlight = (async () => {
    let result;
    do {
      refreshAgain = false;
      result = await refreshFiltersOnce();
    } while (refreshAgain);
    return result;
  })().finally(() => { refreshInFlight = null; });
  return refreshInFlight;
}

async function loadStaticMetadata() {
  if (staticMetadataCache) return staticMetadataCache;
  try {
    const response = await fetch(chrome.runtime.getURL("rules/generated/ruleset-metadata.json"));
    staticMetadataCache = response.ok ? await response.json() : { rulesets: [] };
  } catch {
    staticMetadataCache = { rulesets: [] };
  }
  return staticMetadataCache;
}

async function countPackagedRuleset(resourceId, manifestResources) {
  const resource = manifestResources.find(item => item.id === resourceId);
  if (!resource) return 0;
  try {
    const response = await fetch(chrome.runtime.getURL(resource.path));
    const rules = response.ok ? await response.json() : [];
    return Array.isArray(rules) ? rules.length : 0;
  } catch {
    return 0;
  }
}

async function syncStaticRulesets() {
  staticSyncQueue = staticSyncQueue.catch(() => {}).then(syncStaticRulesetsCore);
  return staticSyncQueue;
}

async function syncStaticRulesetsCore() {
  const settings = await getSettings();
  const manifestResources = chrome.runtime.getManifest().declarative_net_request?.rule_resources || [];
  const managedIds = manifestResources
    .map(item => item.id)
    .filter(id => Object.values(MANAGED_SEED_RULESETS).includes(id) || /^(ads|tracking|annoyances|malware)_static_/.test(id));

  const enabledNow = await chrome.declarativeNetRequest.getEnabledRulesets();
  const disableFirst = enabledNow.filter(id => managedIds.includes(id));
  if (disableFirst.length) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: disableFirst });
  }

  const seedToEnable = [];
  for (const [feature, id] of Object.entries(MANAGED_SEED_RULESETS)) {
    if (featureEnabled(settings, feature) && managedIds.includes(id)) seedToEnable.push(id);
  }
  if (seedToEnable.length) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: seedToEnable });
  }

  const metadata = await loadStaticMetadata();
  const groups = {};
  for (const feature of STATIC_PRIORITY) groups[feature] = [];
  for (const entry of metadata.rulesets || []) {
    if (groups[entry.feature] && featureEnabled(settings, entry.feature)) groups[entry.feature].push(entry);
  }
  for (const feature of STATIC_PRIORITY) groups[feature].sort((a, b) => a.index - b.index);

  let available = await chrome.declarativeNetRequest.getAvailableStaticRuleCount();
  let enabledCount = seedToEnable.length;
  const generatedToEnable = [];
  let progress = true;
  while (progress && enabledCount < MAX_STATIC_RULESETS_ENABLED) {
    progress = false;
    for (const feature of STATIC_PRIORITY) {
      const candidate = groups[feature].shift();
      if (!candidate) continue;
      progress = true;
      if (candidate.count <= available && enabledCount < MAX_STATIC_RULESETS_ENABLED) {
        generatedToEnable.push(candidate.id);
        available -= candidate.count;
        enabledCount += 1;
      }
    }
  }

  if (generatedToEnable.length) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: generatedToEnable });
  }
  const generatedRuleCount = (metadata.rulesets || [])
    .filter(item => generatedToEnable.includes(item.id))
    .reduce((sum, item) => sum + item.count, 0);
  const coreRuleCounts = await Promise.all(seedToEnable.map(id => countPackagedRuleset(id, manifestResources)));
  const enabledStaticRules = generatedRuleCount + coreRuleCounts.reduce((sum, count) => sum + count, 0);
  await chrome.storage.local.set({
    enabledStaticRulesets: [...seedToEnable, ...generatedToEnable],
    enabledStaticRules: enabledStaticRules,
    availableStaticRulesAfterSync: available
  });
  return { enabled: [...seedToEnable, ...generatedToEnable], enabledStaticRules };
}


async function syncPrivacyRules() {
  privacySyncQueue = privacySyncQueue.catch(() => {}).then(syncPrivacyRulesCore);
  return privacySyncQueue;
}

async function syncPrivacyRulesCore() {
  const [settings, stored] = await Promise.all([
    getSettings(),
    chrome.storage.local.get("trackerOverrides")
  ]);
  const desired = [
    ...buildPrivacyRules(settings),
    ...buildTrackerOverrideRules(stored.trackerOverrides || {})
  ];
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.filter(rule => isPrivacyRuleId(rule.id)).map(rule => rule.id);
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: desired });
    await chrome.storage.local.set({ privacyHeaderStatus: desired.some(r => r.action.type === "modifyHeaders") ? "active" : "disabled" });
  } catch (error) {
    const fallback = desired.filter(rule => rule.action.type !== "modifyHeaders");
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: fallback });
    await chrome.storage.local.set({ privacyHeaderStatus: "content-signal-only", privacyHeaderError: String(error) });
  }
}

async function syncPrivacyContentScript() {
  privacyScriptSyncQueue = privacyScriptSyncQueue.catch(() => {}).then(syncPrivacyContentScriptCore);
  return privacyScriptSyncQueue;
}

async function syncPrivacyContentScriptCore() {
  const settings = await getSettings();
  const id = "advanced-blocker-privacy-signals";
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
    if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [id] });
    if (settings.antiTracking && settings.privacySignals) {
      await chrome.scripting.registerContentScripts([{
        id,
        matches: ["http://*/*", "https://*/*"],
        js: ["privacy-signals.js"],
        allFrames: true,
        runAt: "document_start",
        world: "MAIN",
        persistAcrossSessions: true
      }]);
    }
  } catch (error) {
    console.warn("Could not register MAIN-world privacy signals", error);
  }
}

async function syncScriptlets() {
  scriptletSyncQueue = scriptletSyncQueue.catch(() => {}).then(syncScriptletsCore);
  return scriptletSyncQueue;
}

async function syncScriptletsCore() {
  const settings = await getSettings();
  const id = "advanced-blocker-scriptlets";
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
    if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [id] });
    if (settings.scriptlets) {
      await chrome.scripting.registerContentScripts([{
        id,
        matches: ["http://*/*", "https://*/*"],
        js: ["scriptlets.js"],
        allFrames: true,
        runAt: "document_start",
        world: "MAIN",
        persistAcrossSessions: true
      }]);
    }
  } catch (error) {
    console.warn("Could not register MAIN-world scriptlets", error);
  }
}

async function syncPopupGuard() {
  popupGuardSyncQueue = popupGuardSyncQueue.catch(() => {}).then(syncPopupGuardCore);
  return popupGuardSyncQueue;
}

async function syncPopupGuardCore() {
  const settings = await getSettings();
  const id = "advanced-blocker-popup-guard";
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [id] });
    if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [id] });
    if (settings.popupGuard) {
      await chrome.scripting.registerContentScripts([{
        id,
        matches: ["http://*/*", "https://*/*"],
        js: ["popup-guard.js"],
        allFrames: true,
        runAt: "document_start",
        world: "MAIN",
        persistAcrossSessions: true
      }]);
    }
  } catch (error) {
    console.warn("Could not register MAIN-world popup guard", error);
  }
}

async function scheduleRefresh() {
  const settings = await getSettings();
  const period = Math.max(30, Number(settings.refreshMinutes) || DEFAULT_SETTINGS.refreshMinutes);
  await chrome.alarms.clear("refresh");
  chrome.alarms.create("refresh", { periodInMinutes: period });
}

async function getTrustEntries() {
  const { trustEntries = {} } = await chrome.storage.local.get("trustEntries");
  return trustEntries || {};
}

async function pruneTrustEntries(entries, now = Date.now()) {
  let changed = false;
  const next = { ...entries };
  for (const [domain, entry] of Object.entries(next)) {
    if (entry?.until !== 0 && Number(entry?.until || 0) <= now) {
      delete next[domain];
      changed = true;
    }
  }
  if (changed) await chrome.storage.local.set({ trustEntries: next });
  return next;
}

async function getPauseState(host = "") {
  const now = Date.now();
  const stored = await chrome.storage.local.get(["globalPauseUntil", "trustEntries"]);
  const globalPauseUntil = Number(stored.globalPauseUntil || 0);
  const globalPaused = globalPauseUntil > now;
  const entries = await pruneTrustEntries(stored.trustEntries || {}, now);
  let trustedDomain = "";
  let trustUntil = null;
  for (const [domain, entry] of Object.entries(entries)) {
    if (domainMatches(host, domain) && isTrustActive(entry, now)) {
      trustedDomain = domain;
      trustUntil = entry.until;
      break;
    }
  }
  return { globalPaused, globalPauseUntil, trusted: Boolean(trustedDomain), trustedDomain, trustUntil };
}

async function applyTrustRules() {
  trustSyncQueue = trustSyncQueue.catch(() => {}).then(applyTrustRulesCore);
  return trustSyncQueue;
}

async function applyTrustRulesCore() {
  const now = Date.now();
  const [settings, stored] = await Promise.all([
    getSettings(),
    chrome.storage.local.get(["globalPauseUntil", "trustEntries", "imageAllowances"])
  ]);
  const entries = await pruneTrustEntries(stored.trustEntries || {}, now);
  const rules = [];
  if (Number(stored.globalPauseUntil || 0) > now) {
    rules.push({
      id: SESSION_GLOBAL_PAUSE_ID,
      priority: 1_000_000,
      action: { type: "allowAllRequests" },
      condition: { urlFilter: "*", resourceTypes: ["main_frame", "sub_frame"] }
    });
  }
  let index = 0;
  for (const [domain, entry] of Object.entries(entries)) {
    if (!isTrustActive(entry, now) || index >= 900) continue;
    rules.push({
      id: SESSION_TRUST_ID_START + index++,
      priority: 900_000,
      action: { type: "allowAllRequests" },
      condition: { requestDomains: [domain], resourceTypes: ["main_frame", "sub_frame"] }
    });
  }
  // Resource-type allowances: high-priority "allow" beats any block rule, so the
  // chosen types (e.g. images for comics) are never blocked anywhere. This is a
  // deliberate loosening -- it also lets tracking pixels / ad images of that type
  // through, which is the user's explicit trade-off.
  const allowTypes = [];
  if (settings.allowImages) allowTypes.push("image");
  if (settings.allowMedia) allowTypes.push("media");
  if (settings.allowFonts) allowTypes.push("font");
  if (allowTypes.length) {
    rules.push({
      id: SESSION_ALLOWANCE_ID,
      priority: 950_000,
      action: { type: "allow" },
      condition: { resourceTypes: allowTypes, urlFilter: "*" }
    });
  }

  // Per-site "allow images here": permit ALL image requests made while on the
  // listed site (initiator = site), regardless of the image's host -- comic
  // readers typically serve pages from a separate image CDN (third-party), so a
  // first-party-only rule would never match them. Priority 40k beats generic
  // ad/tracker blocks (priority ~1) but stays below the malvertising/malware
  // rulesets (priority 2,000,000), so disguised/malicious ad-images remain
  // blocked even on an allowed site.
  const imageSites = Array.isArray(stored.imageAllowances) ? stored.imageAllowances : [];
  let imgIndex = 0;
  for (const domain of imageSites) {
    if (imgIndex >= 500) break;
    rules.push({
      id: SESSION_IMAGE_ALLOW_START + imgIndex++,
      priority: 40_000,
      action: { type: "allow" },
      condition: { initiatorDomains: [domain], resourceTypes: ["image"] }
    });
  }

  const current = await chrome.declarativeNetRequest.getSessionRules();
  const removeRuleIds = current.map(rule => rule.id);
  try {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules: rules });
  } catch (error) {
    // Never let a bad allowance rule take down trust/pause protection.
    console.warn("Session rule apply failed; retrying without image/type allowances", error);
    const safe = rules.filter(rule => rule.id !== SESSION_ALLOWANCE_ID && rule.id < SESSION_IMAGE_ALLOW_START);
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules: safe });
  }

  const expiries = [Number(stored.globalPauseUntil || 0), ...Object.values(entries).map(entry => Number(entry?.until || 0))]
    .filter(value => value > now)
    .sort((a, b) => a - b);
  await chrome.alarms.clear("trust-expiry");
  if (expiries.length) chrome.alarms.create("trust-expiry", { when: expiries[0] + 250 });
  cosmeticHostCache.clear();
}

async function trustSite(domain, durationMs) {
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error("Invalid domain");
  trustMutationQueue = trustMutationQueue.catch(() => {}).then(async () => {
    const entries = await getTrustEntries();
    if (durationMs === null || durationMs === false) delete entries[normalized];
    else entries[normalized] = { until: durationMs === 0 ? 0 : Date.now() + Number(durationMs), createdAt: Date.now() };
    await chrome.storage.local.set({ trustEntries: entries });
    await applyTrustRules();
    return getPauseState(normalized);
  });
  return trustMutationQueue;
}

async function pauseGlobal(durationMs) {
  trustMutationQueue = trustMutationQueue.catch(() => {}).then(async () => {
    const until = durationMs ? Date.now() + Number(durationMs) : 0;
    await chrome.storage.local.set({ globalPauseUntil: until });
    await applyTrustRules();
    return { globalPauseUntil: until };
  });
  return trustMutationQueue;
}

function cosmeticApplies(rule, host) {
  const includes = rule.domains || rule.includeDomains || [];
  const excludes = rule.excludedDomains || rule.excludeDomains || [];
  if (excludes.some(domain => domainMatches(host, domain))) return false;
  return includes.length === 0 || includes.some(domain => domainMatches(host, domain));
}

async function loadPackagedCosmetics() {
  if (packagedCosmeticCache) return packagedCosmeticCache;
  const output = { ads: [], tracking: [], annoyances: [], malware: [] };
  await Promise.all(Object.keys(output).map(async feature => {
    try {
      const response = await fetch(chrome.runtime.getURL(`rules/generated/cosmetic-${feature}.json`));
      if (response.ok) output[feature] = await response.json();
    } catch {}
  }));
  packagedCosmeticCache = output;
  return output;
}

async function getCosmeticForHost(host, settings) {
  const cacheKey = `${host}:${settings.adBlocking}:${settings.antiTracking}:${settings.annoyances}`;
  if (cosmeticHostCache.has(cacheKey)) return cosmeticHostCache.get(cacheKey);
  const [packaged, stored] = await Promise.all([
    loadPackagedCosmetics(),
    chrome.storage.local.get(["dynamicCosmetic", "customCosmetic"])
  ]);
  const selected = [];
  const exceptions = new Set();
  const allRules = [];
  for (const [feature, rules] of Object.entries(packaged)) {
    if (featureEnabled(settings, feature)) allRules.push(...rules.map(rule => ({ ...rule, feature })));
  }
  for (const rule of stored.dynamicCosmetic || []) {
    if (rule.feature === "custom" || featureEnabled(settings, rule.feature || "tracking")) allRules.push(rule);
  }
  for (const rule of allRules) {
    if (!cosmeticApplies(rule, host)) continue;
    if (rule.exception) exceptions.add(rule.selector);
    else selected.push(rule.selector);
  }
  const selectors = [...new Set(selected.filter(selector => !exceptions.has(selector)))].slice(0, MAX_COSMETIC_PER_PAGE);
  const customSelectors = [];
  const custom = stored.customCosmetic || {};
  for (const [domain, domainSelectors] of Object.entries(custom)) {
    if (domainMatches(host, domain)) customSelectors.push(...(domainSelectors || []));
  }
  const result = { selectors, customSelectors: [...new Set(customSelectors)].slice(0, 500) };
  cosmeticHostCache.set(cacheKey, result);
  return result;
}

async function getDynamicRuleMeta() {
  if (dynamicRuleMetaCache) return dynamicRuleMetaCache;
  const { dynamicRuleMeta = [] } = await chrome.storage.local.get("dynamicRuleMeta");
  dynamicRuleMetaCache = dynamicRuleMeta || [];
  return dynamicRuleMetaCache;
}

async function isMatchedRuleBlocked(rule) {
  if (!rule) return true;
  if (rule.rulesetId === chrome.declarativeNetRequest.DYNAMIC_RULESET_ID || rule.rulesetId === "_dynamic") {
    const meta = await getDynamicRuleMeta();
    return meta[Number(rule.ruleId) - 1]?.action !== "allow";
  }
  if (Object.values(MANAGED_SEED_RULESETS).includes(rule.rulesetId)) return true;
  const metadata = await loadStaticMetadata();
  const ruleset = (metadata.rulesets || []).find(item => item.id === rule.rulesetId);
  return !(ruleset?.allowIds || []).includes(rule.ruleId);
}

async function recordTracker(tabId, item) {
  if (!Number.isInteger(tabId) || tabId < 0 || !item) return;
  const previous = trackerWriteQueues.get(tabId) || Promise.resolve();
  const current = previous.catch(() => {}).then(async () => {
    const settings = await getSettings();
    const key = sessionKey(tabId);
    const stored = await chrome.storage.session.get(key);
    const events = Array.isArray(stored[key]) ? stored[key] : [];
    events.push({ ...item, time: Date.now() });
    const max = Math.max(50, Number(settings.maxTrackerEventsPerTab) || 250);
    if (events.length > max) events.splice(0, events.length - max);
    await chrome.storage.session.set({ [key]: events });
  });
  trackerWriteQueues.set(tabId, current);
  try { await current; }
  finally { if (trackerWriteQueues.get(tabId) === current) trackerWriteQueues.delete(tabId); }
}

async function getTabReport(tabId) {
  const key = sessionKey(tabId);
  const stored = await chrome.storage.session.get(key);
  const events = Array.isArray(stored[key]) ? stored[key] : [];
  return { ...summarizeTrackers(events), events: events.slice(-100) };
}

async function incrementGlobalStats(delta) {
  statsWriteQueue = statsWriteQueue.catch(() => {}).then(async () => {
    const { globalStats = {} } = await chrome.storage.local.get("globalStats");
    const next = {
      cleanedLinks: Number(globalStats.cleanedLinks || 0) + Number(delta.cleanedLinks || 0),
      consentActions: Number(globalStats.consentActions || 0) + Number(delta.consentActions || 0),
      zapped: Number(globalStats.zapped || 0) + Number(delta.zapped || 0),
      trackerEvents: Number(globalStats.trackerEvents || 0) + Number(delta.trackerEvents || 0),
      since: globalStats.since || Date.now()
    };
    await chrome.storage.local.set({ globalStats: next });
    return next;
  });
  return statsWriteQueue;
}

async function migrateLegacyState() {
  const stored = await chrome.storage.local.get(["settings", "allowlist", "trustEntries"]);
  if (!stored.settings) await chrome.storage.local.set({ settings: { ...DEFAULT_SETTINGS } });
  if (Array.isArray(stored.allowlist) && stored.allowlist.length && !stored.trustEntries) {
    const trustEntries = {};
    for (const domain of stored.allowlist) {
      const normalized = normalizeDomain(domain);
      if (normalized) trustEntries[normalized] = { until: 0, createdAt: Date.now() };
    }
    await chrome.storage.local.set({ trustEntries });
  }
}

async function setupContextMenus() {
  if (!chrome.contextMenus) return;
  try {
    await chrome.contextMenus.removeAll();
    const items = [
      { id: "apb-trust-hour", title: "Trust this site for 1 hour", contexts: ["action"] },
      { id: "apb-trust-day", title: "Trust this site for 1 day", contexts: ["action"] },
      { id: "apb-resume-site", title: "Resume protection on this site", contexts: ["action"] },
      { id: "apb-zap", title: "Zap an element", contexts: ["action"] },
      { id: "apb-options", title: "Open privacy blocker settings", contexts: ["action"] }
    ];
    for (const item of items) chrome.contextMenus.create(item);
  } catch (error) {
    console.warn("Could not create context menus", error);
  }
}

async function handleContextMenu(info, tab) {
  if (info.menuItemId === "apb-options") {
    await chrome.runtime.openOptionsPage();
    return;
  }
  if (info.menuItemId === "apb-zap") {
    if (Number.isInteger(tab?.id)) await chrome.tabs.sendMessage(tab.id, { type: "startZapper" }).catch(() => {});
    return;
  }
  let host = "";
  try { host = new URL(tab?.url || "").hostname; } catch {}
  if (!host) return;
  if (info.menuItemId === "apb-trust-hour") await trustSite(host, 3_600_000);
  else if (info.menuItemId === "apb-trust-day") await trustSite(host, 86_400_000);
  else if (info.menuItemId === "apb-resume-site") await trustSite(host, null);
  else return;
  if (Number.isInteger(tab?.id)) await chrome.tabs.reload(tab.id).catch(() => {});
}

async function setCustomFilterTextState(value) {
  const text = String(value || "");
  if (new TextEncoder().encode(text).length > MAX_INLINE_FILTER_BYTES) throw new Error("Custom filters exceed 1 MiB");
  customFilterMutationQueue = customFilterMutationQueue.catch(() => {}).then(async () => {
    await chrome.storage.local.set({ customFilterText: text });
    return refreshFilters();
  });
  return customFilterMutationQueue;
}

async function setBuiltinStateValue(id, enabled) {
  if (!BUILTIN_LISTS.some(item => item.id === id)) throw new Error("Unknown built-in list");
  builtinStateMutationQueue = builtinStateMutationQueue.catch(() => {}).then(async () => {
    const states = await getBuiltinStates();
    states[id] = Boolean(enabled);
    await chrome.storage.local.set({ builtinStates: states });
    const update = await refreshFilters();
    return { states, update };
  });
  return builtinStateMutationQueue;
}

async function mutateCustomCosmetic(domainValue, selectorValue, remove = false) {
  const domain = normalizeDomain(domainValue);
  const selector = String(selectorValue || "").trim();
  if (!domain) throw new Error("Invalid domain");
  if (!remove && (!selector || selector.length > 1200 || /[{}]/.test(selector))) throw new Error("Invalid selector");
  cosmeticMutationQueue = cosmeticMutationQueue.catch(() => {}).then(async () => {
    const { customCosmetic = {} } = await chrome.storage.local.get("customCosmetic");
    if (remove) {
      if (selector) customCosmetic[domain] = (customCosmetic[domain] || []).filter(item => item !== selector);
      else delete customCosmetic[domain];
    } else {
      const set = new Set(customCosmetic[domain] || []);
      set.add(selector);
      customCosmetic[domain] = [...set].slice(0, 500);
    }
    await chrome.storage.local.set({ customCosmetic });
    cosmeticHostCache.clear();
  });
  return cosmeticMutationQueue;
}

async function setTrackerOverrideState(siteDomain, trackerDomain, requestedStatus) {
  const site = normalizeDomain(siteDomain);
  const tracker = normalizeDomain(trackerDomain);
  const status = ["allow", "block", "default"].includes(requestedStatus) ? requestedStatus : "default";
  if (!site || !tracker) throw new Error("Invalid tracker override domain");

  trackerOverrideMutationQueue = trackerOverrideMutationQueue.catch(() => {}).then(async () => {
    const stored = await chrome.storage.local.get("trackerOverrides");
    const overrides = sanitizeTrackerOverrides(stored.trackerOverrides || {});
    const siteRules = { ...(overrides[site] || {}) };
    if (status === "default") delete siteRules[tracker];
    else siteRules[tracker] = status;
    if (Object.keys(siteRules).length) overrides[site] = siteRules;
    else delete overrides[site];
    const sanitized = sanitizeTrackerOverrides(overrides);
    await chrome.storage.local.set({ trackerOverrides: sanitized });
    await syncPrivacyRules();
    return getSiteTrackerOverrides(sanitized, site);
  });
  return trackerOverrideMutationQueue;
}

async function syncAll({ updateLists = false } = {}) {
  await migrateLegacyState();
  await Promise.allSettled([
    syncStaticRulesets(),
    syncPrivacyRules(),
    syncPrivacyContentScript(),
    syncScriptlets(),
    syncPopupGuard(),
    applyTrustRules(),
    scheduleRefresh()
  ]);
  if (updateLists) await refreshFilters();
}

chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: true }).catch(() => {});
chrome.action.setBadgeBackgroundColor({ color: "#365f91" }).catch(() => {});

chrome.runtime.onInstalled.addListener(() => {
  setupContextMenus();
  syncAll({ updateLists: true });
});
chrome.runtime.onStartup.addListener(() => { syncAll({ updateLists: false }); });
if (chrome.contextMenus?.onClicked) {
  chrome.contextMenus.onClicked.addListener((info, tab) => { handleContextMenu(info, tab).catch(() => {}); });
}

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "refresh") refreshFilters();
  if (alarm.name === "trust-expiry") applyTrustRules();
});

chrome.tabs.onRemoved.addListener(tabId => {
  trackerWriteQueues.delete(tabId);
  chrome.storage.session.remove([sessionKey(tabId), contentCounterKey(tabId)]).catch(() => {});
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading" || changeInfo.url) {
    chrome.storage.session.remove([sessionKey(tabId), contentCounterKey(tabId)]).catch(() => {});
  }
  if (!changeInfo.url) return;

  // Flag top-level navigations that jumped to a different site without the user
  // clicking a link there. This catches same-tab click-hijacks, which the MAIN
  // world guard cannot stop because window.location is unforgeable. Labelled
  // "unexplained" rather than malicious: a JS navigation, form post or
  // target=_blank link can land here legitimately.
  const previousUrl = lastTabUrls.get(tabId) || "";
  lastTabUrls.set(tabId, changeInfo.url);
  if (!previousUrl) return;

  const fromHost = hostOf(previousUrl);
  const toHost = hostOf(changeInfo.url);
  if (!fromHost || !toHost) return;
  if (registrableApprox(fromHost) === registrableApprox(toHost)) return;

  const click = recentAnchorClicks.get(tabId);
  const explained = click
    && Date.now() - click.at < ANCHOR_CLICK_GRACE_MS
    && registrableApprox(click.host) === registrableApprox(toHost);
  if (explained) return;

  logRedirectEvent({
    kind: "unexplained-navigation",
    at: Date.now(),
    fromHost,
    from: previousUrl.slice(0, 1500),
    to: changeInfo.url.slice(0, 1500),
    toHost
  });
});
chrome.tabs.onRemoved.addListener(tabId => {
  recentAnchorClicks.delete(tabId);
  lastTabUrls.delete(tabId);
});

try {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(info => {
    (async () => {
      const blocked = await isMatchedRuleBlocked(info.rule);
      if (!blocked) return;
      const sourceUrl = info.request.initiator || info.request.documentUrl || "";
      const malware = String(info.rule.rulesetId || "").includes("malware");
      const item = classifyRequest(info.request.url, { sourceUrl, blocked: true, malware });
      if (item) {
        await recordTracker(info.request.tabId, item);
        await incrementGlobalStats({ trackerEvents: 1 });
      }
    })().catch(() => {});
  });
} catch {}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.settings) {
    cosmeticHostCache.clear();
    Promise.allSettled([syncStaticRulesets(), syncPrivacyRules(), syncPrivacyContentScript(), syncScriptlets(), syncPopupGuard(), applyTrustRules(), scheduleRefresh()]);
  }
  if (changes.trustEntries || changes.globalPauseUntil || changes.imageAllowances) applyTrustRules();
  if (changes.trackerOverrides) syncPrivacyRules();
  if (changes.customFilterText) refreshFilters();
  if (changes.builtinStates || changes.customLists) dynamicRuleMetaCache = null;
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message?.type) {
      case "getContentConfig": { 
        const host = normalizeDomain(message.host);
        const [settings, pause] = await Promise.all([getSettings(), getPauseState(host)]);
        if (pause.globalPaused || pause.trusted) {
          sendResponse({ enabled: false, settings, pause });
          return;
        }
        const cosmetics = await getCosmeticForHost(host, settings);
        sendResponse({ enabled: true, settings, pause, ...cosmetics });
        return;
      }
      case "observeResources": {
        const tabId = sender.tab?.id;
        const sourceUrl = message.sourceUrl || sender.url || "";
        let added = 0;
        for (const url of (message.urls || []).slice(0, 250)) {
          const item = classifyRequest(url, { sourceUrl, blocked: false });
          if (!item || !item.thirdParty) continue;
          await recordTracker(tabId, item);
          added += 1;
        }
        if (added) await incrementGlobalStats({ trackerEvents: added });
        sendResponse({ ok: true, added });
        return;
      }
      case "classifyDestinations": {
        sendResponse({ matches: (message.urls || []).slice(0, 100).map(url => classifyDestination(url)) });
        return;
      }
      case "contentActivity": {
        const tabId = sender.tab?.id;
        if (!Number.isInteger(tabId)) { sendResponse({ ok: false }); return; }
        const key = contentCounterKey(tabId);
        const stored = await chrome.storage.session.get(key);
        const previous = stored[key] || {};
        const current = message.counters || {};
        const delta = {
          cleanedLinks: Math.max(0, Number(current.cleanedLinks || 0) - Number(previous.cleanedLinks || 0)),
          consentActions: Math.max(0, Number(current.consentActions || 0) - Number(previous.consentActions || 0)),
          zapped: Math.max(0, Number(current.zapped || 0) - Number(previous.zapped || 0))
        };
        await chrome.storage.session.set({ [key]: current });
        await incrementGlobalStats(delta);
        sendResponse({ ok: true });
        return;
      }
      case "getPopupState": {
        const tabId = Number(message.tabId);
        const [settings, pause, report, stored, badge] = await Promise.all([
          getSettings(),
          getPauseState(message.host || ""),
          getTabReport(tabId),
          chrome.storage.local.get([
            "ruleCount", "enabledStaticRules", "enabledStaticRulesets", "lastUpdate", "lastUpdateError",
            "globalStats", "privacyHeaderStatus", "trackerOverrides", "imageAllowances"
          ]),
          Number.isInteger(tabId) ? chrome.action.getBadgeText({ tabId }) : Promise.resolve("0")
        ]);
        sendResponse({
          settings, pause, report,
          blockedOnTab: Number.parseInt(badge || "0", 10) || report.blocked,
          dynamicRules: stored.ruleCount || 0,
          staticRules: stored.enabledStaticRules || 0,
          enabledStaticRulesets: stored.enabledStaticRulesets || [],
          lastUpdate: stored.lastUpdate || 0,
          lastUpdateError: stored.lastUpdateError || "",
          globalStats: stored.globalStats || {},
          privacyHeaderStatus: stored.privacyHeaderStatus || "unknown",
          trackerOverrides: getSiteTrackerOverrides(stored.trackerOverrides || {}, message.host || ""),
          imageAllowedHere: (Array.isArray(stored.imageAllowances) ? stored.imageAllowances : [])
            .includes(normalizeDomain(message.host || ""))
        });
        return;
      }
      case "setFeature": {
        const allowed = new Set(Object.keys(DEFAULT_SETTINGS));
        if (!allowed.has(message.key)) throw new Error("Unknown setting");
        const settings = await setSettings({ [message.key]: message.value });
        // Respond immediately: the setting is now durably stored. Running the
        // heavy sync jobs (esp. refreshFilters, which fetches large remote lists)
        // before responding kept the service worker busy for many seconds, and a
        // tab close in that window could tear it down mid-handler. Jobs are
        // idempotent and also re-triggered by the storage.onChanged listener.
        sendResponse({ ok: true, settings });
        const jobs = [syncStaticRulesets(), syncPrivacyRules(), syncPrivacyContentScript(), syncScriptlets(), syncPopupGuard(), applyTrustRules()];
        if (["adBlocking", "antiTracking", "annoyances", "malwareProtection"].includes(message.key)) jobs.push(refreshFilters());
        Promise.allSettled(jobs).catch(() => {});
        return;
      }
      case "setSettings": {
        const patch = {};
        for (const [key, value] of Object.entries(message.patch || {})) {
          if (Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key)) patch[key] = value;
        }
        const settings = await setSettings(patch);
        sendResponse({ ok: true, settings });
        const jobs = [syncStaticRulesets(), syncPrivacyRules(), syncPrivacyContentScript(), syncScriptlets(), syncPopupGuard(), applyTrustRules(), scheduleRefresh()];
        if (["adBlocking", "antiTracking", "annoyances", "malwareProtection"].some(key => Object.prototype.hasOwnProperty.call(patch, key))) jobs.push(refreshFilters());
        Promise.allSettled(jobs).catch(() => {});
        return;
      }
      case "setTrackerOverride": {
        const overrides = await setTrackerOverrideState(message.siteDomain, message.trackerDomain, message.status);
        sendResponse({ ok: true, overrides });
        return;
      }
      case "setCustomFilterText": {
        sendResponse(await setCustomFilterTextState(message.text));
        return;
      }
      case "trustSite": {
        sendResponse({ ok: true, pause: await trustSite(message.domain, message.durationMs) });
        return;
      }
      case "pauseGlobal": {
        sendResponse({ ok: true, ...(await pauseGlobal(message.durationMs)) });
        return;
      }
      case "setImageAllowance": {
        const domain = normalizeDomain(message.domain);
        if (!domain) throw new Error("Invalid domain");
        const { imageAllowances = [] } = await chrome.storage.local.get("imageAllowances");
        const set = new Set(Array.isArray(imageAllowances) ? imageAllowances : []);
        if (message.enabled) set.add(domain); else set.delete(domain);
        await chrome.storage.local.set({ imageAllowances: [...set].slice(0, 500) });
        await applyTrustRules();
        sendResponse({ ok: true, imageAllowed: Boolean(message.enabled) });
        return;
      }
      case "forceUpdate": {
        sendResponse(await refreshFilters());
        return;
      }
      case "syncStatic": {
        sendResponse({ ok: true, ...(await syncStaticRulesets()) });
        return;
      }
      case "setBuiltinState": {
        const result = await setBuiltinStateValue(message.id, message.enabled);
        sendResponse({ ok: true, ...result });
        return;
      }
      case "getOptionsState": {
        const [settings, states, stored] = await Promise.all([
          getSettings(),
          getBuiltinStates(),
          chrome.storage.local.get([
            "customLists", "trustEntries", "globalPauseUntil", "perListStats", "flaggedExceptions",
            "ruleCount", "totalParsed", "enabledStaticRules", "enabledStaticRulesets", "lastUpdate",
            "lastUpdateError", "globalStats", "privacyHeaderStatus", "customCosmetic",
            "customFilterText", "trackerOverrides", "imageAllowances", "redirectEvents"
          ])
        ]);
        sendResponse({ settings, builtinStates: states, builtinLists: BUILTIN_LISTS, ...stored });
        return;
      }
      case "addCustomCosmetic": {
        await mutateCustomCosmetic(message.host, message.selector, false);
        sendResponse({ ok: true });
        return;
      }
      case "removeCustomCosmetic": {
        await mutateCustomCosmetic(message.host, message.selector, true);
        sendResponse({ ok: true });
        return;
      }
      case "reportAnchorClick": {
        const tabId = sender?.tab?.id;
        const host = normalizeDomain(message.host);
        if (Number.isInteger(tabId) && host) recentAnchorClicks.set(tabId, { host, at: Date.now() });
        sendResponse({ ok: true });
        return;
      }
      case "reportRedirectEvent": {
        const fromHost = hostOf(message.from || "");
        await logRedirectEvent({
          kind: message.kind === "popup-blocked" ? "popup-blocked" : "unexplained-navigation",
          at: Date.now(),
          fromHost,
          from: String(message.from || "").slice(0, 1500),
          to: String(message.to || "").slice(0, 1500),
          toHost: hostOf(message.to || "")
        });
        sendResponse({ ok: true });
        return;
      }
      case "clearRedirectEvents": {
        await chrome.storage.local.set({ redirectEvents: [] });
        sendResponse({ ok: true });
        return;
      }
      case "blockRedirectDomain": {
        // Append a filter for the offending host to the user's custom filters,
        // reusing the existing custom-filter pipeline so it becomes a real rule.
        const domain = normalizeDomain(message.domain);
        if (!domain) throw new Error("Invalid domain");
        const { customFilterText = "" } = await chrome.storage.local.get("customFilterText");
        const rule = `||${domain}^`;
        const existing = String(customFilterText || "");
        if (existing.split("\n").some(line => line.trim() === rule)) {
          sendResponse({ ok: true, alreadyPresent: true, rule });
          return;
        }
        const next = existing.trim() ? `${existing.replace(/\s*$/, "")}\n${rule}\n` : `${rule}\n`;
        const result = await setCustomFilterTextState(next);
        sendResponse({ ok: result?.ok !== false, rule, ...result });
        return;
      }
      case "clearStats": {
        await chrome.storage.local.set({ globalStats: { since: Date.now() } });
        sendResponse({ ok: true });
        return;
      }
      case "exportStatic": {
        const dynamic = await chrome.declarativeNetRequest.getDynamicRules();
        const filterRules = dynamic.filter(rule => rule.id <= FILTER_RULE_ID_MAX);
        sendResponse({
          rules: filterRules.map((rule, index) => ({ ...rule, id: index + 1 })).slice(0, 30000),
          total: filterRules.length
        });
        return;
      }
      default:
        sendResponse({ ok: false, error: "Unknown message" });
    }
  })().catch(error => {
    console.error("Message handler failed", message?.type, error);
    sendResponse({ ok: false, error: String(error?.message || error) });
  });
  return true;
});
