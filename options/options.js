const $ = id => document.getElementById(id);
const manifest = chrome.runtime.getManifest();
const SETTING_DEFS = [
  ["adBlocking", "Ad blocking", "Network and cosmetic advertisement filtering"],
  ["antiTracking", "Anti-tracking", "Trackers, link cleaning, privacy headers and signals"],
  ["neverConsent", "Never-consent", "Reject supported consent platforms automatically"],
  ["annoyances", "Annoyance blocking", "Popups, overlays and nuisance elements"],
  ["malwareProtection", "Malware protection", "Block destinations from the enabled malware list"],
  ["redirectProtection", "Redirect protection", "Unwrap known click-tracking redirects"],
  ["serpProtection", "Search intelligence", "Flag recognized tracker destinations in search results"],
  ["privacySignals", "GPC and DNT", "Send browser privacy preference signals"],
  ["scriptlets", "Scriptlets", "Run page-side neutralizers (anti-adblock bait, right-click blockers)"],
  ["stripTrackingParams", "Tracking-parameter removal", "Remove common advertising click identifiers"],
  ["socialWidgets", "Social widgets", "Hide embedded share and follow widgets"],
  ["signInPrompts", "Sign-in prompts", "Hide common third-party sign-in prompts"],
  ["appBanners", "App banners", "Hide install-our-app prompts"],
  ["youtubeShorts", "YouTube Shorts", "Hide Shorts navigation and shelves"],
  ["socialReels", "Social Reels", "Hide common short-video/Reels surfaces"],
  ["allowImages", "Allow images (loosen)", "Never block image requests — fixes broken comics/manga"],
  ["allowMedia", "Allow media (loosen)", "Never block video/audio requests"],
  ["allowFonts", "Allow fonts (loosen)", "Never block web font requests"]
];
const VALID_FEATURES = ["ads", "tracking", "annoyances", "malware", "custom"];
let state;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function validHttpUrl(value) { try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; } }
function validDomain(value) {
  const domain = String(value || "").toLowerCase().replace(/^\.+|\.+$/g, "");
  return domain && domain.length <= 253 && !domain.includes("..") && /^[a-z0-9.-]+$/.test(domain);
}
function say(message) {
  $("status").textContent = message;
  $("status").classList.add("show");
  setTimeout(() => $("status").classList.remove("show"), 2400);
}
function download(name, data) {
  const url = URL.createObjectURL(new Blob([data], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function refreshState() {
  // The service worker may be cold when the page opens; a raced/failed first
  // message must never leave us rendering with empty settings (which would look
  // like every toggle reverted). Retry until we get a state that has settings.
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const next = await chrome.runtime.sendMessage({ type: "getOptionsState" });
      if (next && next.settings) { state = next; render(); return; }
    } catch { /* SW waking up */ }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  if (state && state.settings) render(); // keep last good state rather than blanking
}

// Live-refresh if settings change elsewhere (popup, another options tab, sync).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.settings || changes.trustEntries || changes.imageAllowances ||
      changes.customLists || changes.builtinStates || changes.trackerOverrides) {
    refreshState();
  }
});

function renderSettings() {
  $("settings").innerHTML = SETTING_DEFS.map(([key, name, description]) =>
    `<label class="setting"><span><b>${name}</b><small>${description}</small></span><input type="checkbox" data-setting="${key}" ${state.settings?.[key] ? "checked" : ""}></label>`
  ).join("") + `
    <label class="setting"><span><b>Consent behavior</b><small>Reject when possible or only hide banners</small></span><select id="consentMode"><option value="reject" ${state.settings?.consentMode === "reject" ? "selected" : ""}>Reject</option><option value="hide" ${state.settings?.consentMode === "hide" ? "selected" : ""}>Hide only</option></select></label>
    <label class="setting"><span><b>List update interval</b><small>Automatic remote subscription refresh</small></span><select id="refreshMinutes">${[[60,"1 hour"],[360,"6 hours"],[720,"12 hours"],[1440,"24 hours"],[10080,"1 week"]].map(([v,n])=>`<option value="${v}" ${Number(state.settings?.refreshMinutes)===v?"selected":""}>${n}</option>`).join("")}</select></label>`;
  document.querySelectorAll("[data-setting]").forEach(input => input.addEventListener("change", async () => {
    const response = await chrome.runtime.sendMessage({ type: "setFeature", key: input.dataset.setting, value: input.checked });
    say(response?.ok ? "Setting saved" : "Setting failed");
  }));
  $("consentMode").addEventListener("change", () => savePatch({ consentMode: $("consentMode").value }));
  $("refreshMinutes").addEventListener("change", () => savePatch({ refreshMinutes: Number($("refreshMinutes").value) }));
}

async function savePatch(patch) {
  const response = await chrome.runtime.sendMessage({ type: "setSettings", patch });
  say(response?.ok ? "Setting saved" : "Setting failed");
}

function renderBuiltins() {
  $("builtin").innerHTML = (state.builtinLists || []).map(item =>
    `<label class="list-item"><span class="list-main"><b>${escapeHtml(item.name)}</b><small>${escapeHtml(item.url)}</small></span><span class="tag">${escapeHtml(item.feature)}</span><input type="checkbox" data-builtin="${escapeHtml(item.id)}" ${state.builtinStates?.[item.id] ? "checked" : ""}></label>`
  ).join("");
  document.querySelectorAll("[data-builtin]").forEach(input => input.addEventListener("change", async () => {
    const response = await chrome.runtime.sendMessage({ type: "setBuiltinState", id: input.dataset.builtin, enabled: input.checked });
    say(response?.ok ? "List state applied" : "List update failed");
    await refreshState();
  }));
}

function renderCustomSubscriptions() {
  const items = state.customLists || [];
  $("custom").innerHTML = items.length ? items.map((item, index) =>
    `<div class="list-item"><span class="list-main"><b>${escapeHtml(item.name || item.url)}</b><small>${escapeHtml(item.url)}</small></span><span class="tag">${escapeHtml(item.feature || "tracking")}</span><span class="actions"><input type="checkbox" data-custom-toggle="${index}" ${item.enabled ? "checked" : ""}><button class="danger" data-custom-remove="${index}">Remove</button></span></div>`
  ).join("") : '<p class="empty">No custom subscriptions.</p>';
  document.querySelectorAll("[data-custom-toggle]").forEach(input => input.addEventListener("change", () => mutateCustom(Number(input.dataset.customToggle), { enabled: input.checked })));
  document.querySelectorAll("[data-custom-remove]").forEach(button => button.addEventListener("click", () => mutateCustom(Number(button.dataset.customRemove), null)));
}

async function saveCustomLists(items) {
  await chrome.storage.local.set({ customLists: items.slice(0, 50) });
  await chrome.runtime.sendMessage({ type: "forceUpdate" });
}
async function mutateCustom(index, patch) {
  const items = [...(state.customLists || [])];
  if (patch) items[index] = { ...items[index], ...patch };
  else items.splice(index, 1);
  await saveCustomLists(items);
  await refreshState();
}

function renderCustomFilterText() {
  if (document.activeElement !== $("customFilterText")) $("customFilterText").value = state.customFilterText || "";
  const bytes = new TextEncoder().encode($("customFilterText").value).length;
  $("customFilterSize").textContent = `${bytes.toLocaleString()} / 1,048,576 bytes`;
}

$("addTrust")?.addEventListener("click", async () => {
  const domain = ($("trustDomain").value || "").trim();
  $("trustError").textContent = "";
  if (!domain) { $("trustError").textContent = "Enter a domain such as example.com"; return; }
  const durationMs = Number($("trustDomainDuration").value);
  const response = await chrome.runtime.sendMessage({ type: "trustSite", domain, durationMs });
  if (response?.ok) {
    $("trustDomain").value = "";
    say("Excluded site added");
    await refreshState();
  } else {
    $("trustError").textContent = response?.error || "Could not add site (check the domain)";
  }
});

function renderImageAllowances() {
  const sites = Array.isArray(state.imageAllowances) ? state.imageAllowances : [];
  $("imageAllowList").innerHTML = sites.length ? sites.map(domain =>
    `<div class="list-item"><span class="list-main"><b>${escapeHtml(domain)}</b><small>All images allowed on this site</small></span><button data-unallow-image="${escapeHtml(domain)}">Remove</button></div>`
  ).join("") : '<p class="empty">No per-site image allowances.</p>';
  document.querySelectorAll("[data-unallow-image]").forEach(button => button.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "setImageAllowance", domain: button.dataset.unallowImage, enabled: false });
    await refreshState();
  }));
}

function renderTrust() {
  const now = Date.now();
  const entries = Object.entries(state.trustEntries || {}).filter(([, entry]) => entry?.until === 0 || Number(entry?.until) > now);
  $("trustList").innerHTML = entries.length ? entries.map(([domain, entry]) =>
    `<div class="list-item"><span class="list-main"><b>${escapeHtml(domain)}</b><small>${entry.until === 0 ? "Always trusted" : `Until ${new Date(entry.until).toLocaleString()}`}</small></span><button data-untrust="${escapeHtml(domain)}">Resume</button></div>`
  ).join("") : '<p class="empty">No trusted sites.</p>';
  document.querySelectorAll("[data-untrust]").forEach(button => button.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "trustSite", domain: button.dataset.untrust, durationMs: null });
    await refreshState();
  }));
  const globallyPaused = Number(state.globalPauseUntil || 0) > now;
  $("resumeGlobal").disabled = !globallyPaused;
  $("pauseGlobal").disabled = globallyPaused;
}

function renderTrackerOverrides() {
  const rows = [];
  for (const [site, trackerMap] of Object.entries(state.trackerOverrides || {})) {
    for (const [tracker, status] of Object.entries(trackerMap || {})) rows.push({ site, tracker, status });
  }
  rows.sort((a, b) => a.site.localeCompare(b.site) || a.tracker.localeCompare(b.tracker));
  $("trackerOverrides").innerHTML = rows.length ? rows.map(row =>
    `<div class="list-item"><span class="list-main"><b>${escapeHtml(row.tracker)}</b><small>${escapeHtml(row.status)} on ${escapeHtml(row.site)}</small></span><button class="danger" data-override-site="${escapeHtml(row.site)}" data-override-tracker="${escapeHtml(row.tracker)}">Reset</button></div>`
  ).join("") : '<p class="empty">No individual tracker overrides.</p>';
  document.querySelectorAll("[data-override-site]").forEach(button => button.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({
      type: "setTrackerOverride",
      siteDomain: button.dataset.overrideSite,
      trackerDomain: button.dataset.overrideTracker,
      status: "default"
    });
    await refreshState();
  }));
}

function renderZaps() {
  const rows = [];
  for (const [domain, selectors] of Object.entries(state.customCosmetic || {})) {
    for (const selector of selectors || []) rows.push({ domain, selector });
  }
  $("zaps").innerHTML = rows.length ? rows.map(row =>
    `<div class="list-item"><span class="list-main"><b>${escapeHtml(row.domain)}</b><small>${escapeHtml(row.selector)}</small></span><button class="danger" data-zap-domain="${escapeHtml(row.domain)}" data-zap-selector="${escapeHtml(row.selector)}">Remove</button></div>`
  ).join("") : '<p class="empty">No custom element removals.</p>';
  document.querySelectorAll("[data-zap-domain]").forEach(button => button.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "removeCustomCosmetic", host: button.dataset.zapDomain, selector: button.dataset.zapSelector });
    await refreshState();
  }));
}

function renderDiagnostics() {
  const cards = [
    [Number(state.ruleCount || 0).toLocaleString(), "Dynamic rules"],
    [Number(state.enabledStaticRules || 0).toLocaleString(), "Static rules enabled"],
    [(state.enabledStaticRulesets || []).length, "Static rulesets"],
    [Number(state.globalStats?.trackerEvents || 0).toLocaleString(), "Tracker events"],
    [Number(state.globalStats?.cleanedLinks || 0).toLocaleString(), "Links cleaned"],
    [Number(state.globalStats?.consentActions || 0).toLocaleString(), "Consent actions"],
    [Number(state.globalStats?.zapped || 0).toLocaleString(), "Elements zapped"],
    [escapeHtml(state.privacyHeaderStatus || "unknown"), "GPC/DNT headers"]
  ];
  $("diagnosticCards").innerHTML = cards.map(([value, label]) => `<div class="card"><strong>${value}</strong><span>${label}</span></div>`).join("");
  const stats = state.perListStats || [];
  $("statsBody").innerHTML = stats.length ? stats.map(item =>
    `<tr><td title="${escapeHtml(item.url)}">${escapeHtml(item.name || item.id)}</td><td>${escapeHtml(item.feature)}</td><td>${Number(item.rules || 0).toLocaleString()}</td><td>${Number(item.blocks || 0).toLocaleString()}</td><td>${Number(item.exceptions || 0).toLocaleString()}</td><td>${Number(item.cosmetic || 0).toLocaleString()}</td><td class="${item.ok ? "ok" : "fail"}">${item.ok ? "loaded" : escapeHtml(item.error || "failed")}</td></tr>`
  ).join("") : '<tr><td colspan="7" class="empty">Run an update to populate runtime list statistics.</td></tr>';
  const flags = state.flaggedExceptions || [];
  $("flagCount").textContent = flags.length;
  $("audit").innerHTML = flags.length ? flags.slice(0, 200).map(flag =>
    `<div class="audit-item"><code>${escapeHtml(flag.line)}</code><small>${escapeHtml((flag.reasons || []).join("; "))} · ${escapeHtml(flag.source || "")}</small></div>`
  ).join("") : '<p class="empty ok">No broad exceptions flagged in the last update.</p>';
}

function render() {
  $("version").textContent = `v${manifest.version}`;
  renderSettings();
  renderBuiltins();
  renderCustomSubscriptions();
  renderCustomFilterText();
  renderTrust();
  renderImageAllowances();
  renderTrackerOverrides();
  renderZaps();
  renderDiagnostics();
}

$("addList").addEventListener("click", async () => {
  const url = $("listUrl").value.trim();
  const name = $("listName").value.trim();
  const feature = $("listFeature").value;
  $("listError").textContent = "";
  if (!validHttpUrl(url)) { $("listError").textContent = "Enter a valid HTTP(S) filter-list URL."; return; }
  const items = [...(state.customLists || [])];
  if (items.some(item => item.url === url)) { $("listError").textContent = "This subscription already exists."; return; }
  if (items.length >= 50) { $("listError").textContent = "Maximum 50 custom subscriptions."; return; }
  items.push({ id: `custom-${crypto.randomUUID()}`, name: (name || url).slice(0, 200), url, feature, enabled: true });
  await saveCustomLists(items);
  $("listName").value = "";
  $("listUrl").value = "";
  await refreshState();
});

$("customFilterText").addEventListener("input", renderCustomFilterText);
$("applyCustomFilters").addEventListener("click", async () => {
  const text = $("customFilterText").value;
  const bytes = new TextEncoder().encode(text).length;
  if (bytes > 1_048_576) { say("Custom filters exceed 1 MiB"); return; }
  say("Compiling custom filters…");
  const response = await chrome.runtime.sendMessage({ type: "setCustomFilterText", text });
  say(response?.ok ? "Custom filters applied" : (response?.error || "Custom filters retained; update failed"));
  await refreshState();
});

$("update").addEventListener("click", async () => {
  say("Updating lists…");
  const response = await chrome.runtime.sendMessage({ type: "forceUpdate" });
  say(response?.ok ? "Lists updated" : "Update failed; existing remote rules retained");
  await refreshState();
});
$("pauseGlobal").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "pauseGlobal", durationMs: Number($("globalPause").value) });
  await refreshState();
});
$("resumeGlobal").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "pauseGlobal", durationMs: 0 });
  await refreshState();
});
$("clearStats").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "clearStats" });
  await refreshState();
});
$("exportRules").addEventListener("click", async () => {
  const response = await chrome.runtime.sendMessage({ type: "exportStatic" });
  download("advanced-privacy-blocker-dynamic-rules.json", JSON.stringify(response.rules || [], null, 2));
});
$("exportConfig").addEventListener("click", async () => {
  const local = await chrome.storage.local.get([
    "settings", "builtinStates", "customLists", "customFilterText", "trustEntries",
    "trackerOverrides", "customCosmetic"
  ]);
  download("advanced-privacy-blocker-config.json", JSON.stringify({ schema: 3, exportedAt: new Date().toISOString(), ...local }, null, 2));
});
$("importConfig").addEventListener("click", () => $("importFile").click());
$("importFile").addEventListener("change", async event => {
  const file = event.target.files?.[0];
  if (!file || file.size > 3_000_000) { say("Invalid or oversized file"); return; }
  try {
    const data = JSON.parse(await file.text());
    const patch = {};
    if (data.builtinStates && typeof data.builtinStates === "object") patch.builtinStates = data.builtinStates;
    if (Array.isArray(data.customLists)) {
      patch.customLists = data.customLists.filter(item => validHttpUrl(item?.url)).slice(0, 50).map(item => ({
        id: String(item.id || `custom-${crypto.randomUUID()}`),
        name: String(item.name || item.url).slice(0, 200),
        url: item.url,
        feature: VALID_FEATURES.includes(item.feature) ? item.feature : "tracking",
        enabled: Boolean(item.enabled)
      }));
    }
    if (typeof data.customFilterText === "string" && new TextEncoder().encode(data.customFilterText).length <= 1_048_576) {
      patch.customFilterText = data.customFilterText;
    }
    if (data.trustEntries && typeof data.trustEntries === "object") {
      patch.trustEntries = Object.fromEntries(Object.entries(data.trustEntries)
        .filter(([domain, entry]) => validDomain(domain) && (entry?.until === 0 || Number(entry?.until) > Date.now()))
        .slice(0, 900));
    }
    if (data.trackerOverrides && typeof data.trackerOverrides === "object") {
      const clean = {};
      let count = 0;
      for (const [site, trackerMap] of Object.entries(data.trackerOverrides)) {
        if (!validDomain(site) || !trackerMap || typeof trackerMap !== "object") continue;
        const map = {};
        for (const [tracker, status] of Object.entries(trackerMap)) {
          if (!validDomain(tracker) || !["allow", "block"].includes(status) || count >= 2000) continue;
          map[tracker] = status;
          count += 1;
        }
        if (Object.keys(map).length) clean[site] = map;
        if (count >= 2000) break;
      }
      patch.trackerOverrides = clean;
    }
    if (data.customCosmetic && typeof data.customCosmetic === "object") {
      patch.customCosmetic = Object.fromEntries(Object.entries(data.customCosmetic)
        .filter(([domain]) => validDomain(domain)).slice(0, 500)
        .map(([domain, selectors]) => [domain, (Array.isArray(selectors) ? selectors : [])
          .filter(selector => typeof selector === "string" && selector.length <= 1200 && !/[{}]/.test(selector)).slice(0, 500)]));
    }

    if (data.settings && typeof data.settings === "object") {
      await chrome.runtime.sendMessage({ type: "setSettings", patch: data.settings });
    }
    await chrome.storage.local.set(patch);
    await Promise.allSettled([
      chrome.runtime.sendMessage({ type: "forceUpdate" }),
      chrome.runtime.sendMessage({ type: "syncStatic" })
    ]);
    await refreshState();
    say("Configuration imported");
  } catch {
    say("Invalid configuration file");
  }
  event.target.value = "";
});

refreshState();
