const $ = id => document.getElementById(id);
const format = value => Number(value || 0).toLocaleString();
const escapeHtml = value => String(value || "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));

let tab, host, state;

function trackerMarkup(item) {
  const override = state.trackerOverrides?.[item.hostname] || "default";
  return `
    <div class="tracker">
      <div class="tracker-main">
        <b>${escapeHtml(item.name)}</b>
        <small>${escapeHtml(item.organization)} · ${escapeHtml(item.categoryName)} · ${Number(item.count || 0)} request${item.count === 1 ? "" : "s"}</small>
        <small class="hostname">${escapeHtml(item.hostname)}</small>
      </div>
      <span class="state ${item.blocked ? "" : "observed"}">${item.blocked ? "Blocked" : "Observed"}</span>
      <select class="tracker-control" data-tracker-domain="${escapeHtml(item.hostname)}" aria-label="Control ${escapeHtml(item.name)} on this site">
        <option value="default" ${override === "default" ? "selected" : ""}>Default</option>
        <option value="block" ${override === "block" ? "selected" : ""}>Always block</option>
        <option value="allow" ${override === "allow" ? "selected" : ""}>Allow here</option>
      </select>
    </div>`;
}

async function load() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try { host = new URL(tab.url).hostname; } catch { host = ""; }
  $("domain").textContent = host || "Restricted browser page";
  // Retry a cold service-worker so toggles never render blank/unchecked.
  for (let attempt = 0; attempt < 4 && !state?.settings; attempt += 1) {
    try { state = await chrome.runtime.sendMessage({ type: "getPopupState", tabId: tab?.id, host }); } catch {}
    if (!state?.settings) await new Promise(resolve => setTimeout(resolve, 120));
  }
  if (!state?.settings) return;

  for (const input of document.querySelectorAll("[data-setting]")) input.checked = Boolean(state.settings[input.dataset.setting]);
  $("blocked").textContent = format(state.blockedOnTab);
  $("detected").textContent = format(state.report?.detected);
  $("rules").textContent = format(Number(state.dynamicRules || 0) + Number(state.staticRules || 0));

  const allowImagesHere = $("allowImagesHere");
  if (allowImagesHere) {
    allowImagesHere.checked = Boolean(state.imageAllowedHere);
    allowImagesHere.disabled = !host;
  }

  const paused = state.pause?.globalPaused || state.pause?.trusted;
  $("statusPill").textContent = state.pause?.globalPaused ? "Globally paused" : state.pause?.trusted ? "Site trusted" : "Protected";
  $("statusPill").classList.toggle("paused", paused);
  $("trust").classList.toggle("hidden", paused || !host);
  $("trustDuration").classList.toggle("hidden", paused || !host);
  $("resume").classList.toggle("hidden", !paused);

  const trackers = state.report?.trackers || [];
  $("trackerSummary").textContent = `${state.report?.blocked || 0} blocked`;
  $("trackers").innerHTML = trackers.length
    ? trackers.slice(0, 30).map(trackerMarkup).join("")
    : '<p class="empty">No recognized trackers yet. Reload after opening the popup if the page was already loaded.</p>';

  document.querySelectorAll("[data-tracker-domain]").forEach(select => {
    select.addEventListener("change", async () => {
      select.disabled = true;
      const response = await chrome.runtime.sendMessage({
        type: "setTrackerOverride",
        siteDomain: host,
        trackerDomain: select.dataset.trackerDomain,
        status: select.value
      });
      $("message").textContent = response?.ok ? "Tracker rule saved" : "Override failed";
      if (response?.ok && Number.isInteger(tab?.id)) {
        await chrome.tabs.reload(tab.id);
        window.close();
      } else select.disabled = false;
    });
  });
}

for (const input of document.querySelectorAll("[data-setting]")) {
  input.addEventListener("change", async () => {
    input.disabled = true;
    const response = await chrome.runtime.sendMessage({ type: "setFeature", key: input.dataset.setting, value: input.checked });
    input.disabled = false;
    $("message").textContent = response?.ok ? "Saved" : "Failed";
  });
}

$("allowImagesHere").addEventListener("change", async event => {
  if (!host) return;
  event.target.disabled = true;
  const response = await chrome.runtime.sendMessage({ type: "setImageAllowance", domain: host, enabled: event.target.checked });
  $("message").textContent = response?.ok ? "Image rule saved" : "Failed";
  if (response?.ok && Number.isInteger(tab?.id)) { await chrome.tabs.reload(tab.id); window.close(); }
  else event.target.disabled = false;
});

$("trust").addEventListener("click", async () => {
  const durationMs = Number($("trustDuration").value);
  await chrome.runtime.sendMessage({ type: "trustSite", domain: host, durationMs });
  if (tab?.id) chrome.tabs.reload(tab.id);
  window.close();
});
$("resume").addEventListener("click", async () => {
  if (state.pause?.globalPaused) await chrome.runtime.sendMessage({ type: "pauseGlobal", durationMs: 0 });
  else await chrome.runtime.sendMessage({ type: "trustSite", domain: state.pause.trustedDomain || host, durationMs: null });
  if (tab?.id) chrome.tabs.reload(tab.id);
  window.close();
});
$("zap").addEventListener("click", async () => {
  try { await chrome.tabs.sendMessage(tab.id, { type: "startZapper" }); } catch {}
  window.close();
});
$("update").addEventListener("click", async () => {
  $("message").textContent = "Updating…";
  const response = await chrome.runtime.sendMessage({ type: "forceUpdate" });
  $("message").textContent = response?.ok ? "Updated" : "Lists retained";
  await load();
});
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
load();
