// Node test runner: node test/run-tests.mjs   (or: npm test)
//
// Runs two suites without a browser:
//   1. Converter unit tests (lib/converter.test.js)
//   2. Service-worker smoke test -- loads background.js against a mocked chrome.*
//      and exercises every onMessage handler. This catches runtime breakage that
//      syntax checks miss (e.g. calling an Array method on a Set), which would
//      otherwise surface only as a blank popup/options page.
const listeners = {};
const noopEvent = () => ({ addListener: () => {}, removeListener: () => {} });
const store = {};

globalThis.chrome = {
  runtime: {
    getManifest: () => ({ version: "2.1.0", declarative_net_request: { rule_resources: [] } }),
    getURL: p => "file://" + p,
    onInstalled: noopEvent(), onStartup: noopEvent(),
    onMessage: { addListener: fn => { listeners.message = fn; } }
  },
  storage: {
    local: {
      get: async keys => {
        const list = Array.isArray(keys) ? keys : [keys];
        const out = {};
        for (const key of list) if (key in store) out[key] = store[key];
        return out;
      },
      set: async patch => { Object.assign(store, JSON.parse(JSON.stringify(patch))); },
      remove: async () => {}
    },
    session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
    onChanged: noopEvent()
  },
  declarativeNetRequest: {
    setExtensionActionOptions: async () => {},
    getDynamicRules: async () => [], updateDynamicRules: async () => {},
    getSessionRules: async () => [], updateSessionRules: async () => {},
    getEnabledRulesets: async () => [], updateEnabledRulesets: async () => {},
    getAvailableStaticRuleCount: async () => 30000,
    isRegexSupported: async ({ regex }) => {
      try { new RegExp(regex); return { isSupported: true }; }
      catch { return { isSupported: false, reason: "syntaxError" }; }
    },
    onRuleMatchedDebug: noopEvent()
  },
  action: { setBadgeBackgroundColor: async () => {}, getBadgeText: async () => "0", setBadgeText: async () => {} },
  alarms: { create: () => {}, clear: async () => {}, onAlarm: noopEvent() },
  tabs: { onRemoved: noopEvent(), onUpdated: noopEvent(), query: async () => [], reload: async () => {}, sendMessage: async () => {} },
  scripting: {
    getRegisteredContentScripts: async () => [],
    registerContentScripts: async () => {}, unregisterContentScripts: async () => {}
  },
  contextMenus: { create: () => {}, removeAll: cb => cb && cb(), onClicked: noopEvent() }
};

let failed = 0;

// --- 1. converter unit tests -------------------------------------------------
const converterTests = await import("../lib/converter.test.js");
const converterResult = await converterTests.runTests();
failed += converterResult.failed;

// --- 2. service-worker handler smoke test -----------------------------------
await import("../background.js");
if (typeof listeners.message !== "function") {
  console.error("FAIL: background.js registered no onMessage handler");
  failed += 1;
} else {
  const call = message => new Promise(resolve => listeners.message(message, {}, resolve));
  const cases = [
    ["getOptionsState", { type: "getOptionsState" }],
    ["getPopupState", { type: "getPopupState", tabId: 1, host: "example.com" }],
    ["getContentConfig", { type: "getContentConfig", host: "example.com" }],
    ["setFeature", { type: "setFeature", key: "allowImages", value: true }],
    ["setSettings", { type: "setSettings", patch: { scriptlets: false } }],
    ["setImageAllowance", { type: "setImageAllowance", domain: "comic.example", enabled: true }],
    ["trustSite", { type: "trustSite", domain: "example.com", durationMs: 0 }],
    ["setBuiltinState", { type: "setBuiltinState", id: "abpindo", enabled: false }],
    ["setTrackerOverride", { type: "setTrackerOverride", siteDomain: "a.com", trackerDomain: "b.com", status: "allow" }],
    ["classifyDestinations", { type: "classifyDestinations", urls: ["https://doubleclick.net/x"] }],
    ["addCustomCosmetic", { type: "addCustomCosmetic", host: "a.com", selector: ".ad" }],
    ["syncStatic", { type: "syncStatic" }],
    ["clearStats", { type: "clearStats" }],
    ["exportStatic", { type: "exportStatic" }]
  ];
  let handlerFails = 0;
  for (const [name, message] of cases) {
    const response = await call(message);
    if (!response || response.error !== undefined || response.ok === false) {
      console.error(`FAIL handler ${name}: ${JSON.stringify(response).slice(0, 140)}`);
      handlerFails += 1;
    }
  }
  // Settings written through the handlers must survive a re-read.
  const reopened = await call({ type: "getOptionsState" });
  if (!reopened?.settings) { console.error("FAIL: getOptionsState returned no settings"); handlerFails += 1; }
  else if (reopened.settings.allowImages !== true) { console.error("FAIL: setting did not persist"); handlerFails += 1; }

  console.log(`Service worker: ${cases.length - handlerFails}/${cases.length} handlers ok, persistence ${reopened?.settings?.allowImages === true ? "ok" : "FAILED"}`);
  failed += handlerFails;
}

console.log(failed ? `\n${failed} test(s) failed.` : "\nAll tests passed.");
process.exit(failed ? 1 : 0);
