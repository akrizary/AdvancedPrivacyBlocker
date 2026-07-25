export const DEFAULT_SETTINGS = Object.freeze({
  adBlocking: true,
  antiTracking: true,
  neverConsent: true,
  annoyances: true,
  malwareProtection: true,
  redirectProtection: true,
  serpProtection: true,
  privacySignals: true,
  scriptlets: true,
  allowImages: false,
  allowMedia: false,
  allowFonts: false,
  stripTrackingParams: true,
  socialWidgets: true,
  signInPrompts: true,
  appBanners: true,
  youtubeShorts: false,
  socialReels: false,
  consentMode: "reject",
  refreshMinutes: 720,
  maxTrackerEventsPerTab: 250
});

let settingsWriteQueue = Promise.resolve();

const BOOLEAN_KEYS = new Set(Object.entries(DEFAULT_SETTINGS)
  .filter(([, value]) => typeof value === "boolean")
  .map(([key]) => key));

export function sanitizeSettings(input = {}) {
  const out = { ...DEFAULT_SETTINGS };
  for (const [key, value] of Object.entries(input || {})) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key)) continue;
    if (BOOLEAN_KEYS.has(key)) out[key] = Boolean(value);
    else if (key === "consentMode") out[key] = value === "hide" ? "hide" : "reject";
    else if (key === "refreshMinutes") out[key] = Math.min(10080, Math.max(30, Number(value) || DEFAULT_SETTINGS.refreshMinutes));
    else if (key === "maxTrackerEventsPerTab") out[key] = Math.min(2000, Math.max(50, Number(value) || DEFAULT_SETTINGS.maxTrackerEventsPerTab));
  }
  return out;
}

export async function getSettings() {
  const { settings = {} } = await chrome.storage.local.get("settings");
  return sanitizeSettings(settings);
}

export async function setSettings(patch) {
  settingsWriteQueue = settingsWriteQueue.catch(() => {}).then(async () => {
    const current = await getSettings();
    const next = sanitizeSettings({ ...current, ...patch });
    await chrome.storage.local.set({ settings: next });
    return next;
  });
  return settingsWriteQueue;
}

export function domainMatches(host, domain) {
  if (!host || !domain) return false;
  const h = String(host).toLowerCase().replace(/^\.+|\.+$/g, "");
  const d = String(domain).toLowerCase().replace(/^\.+|\.+$/g, "");
  return h === d || h.endsWith(`.${d}`);
}

export function normalizeDomain(value) {
  try {
    const raw = String(value || "").trim();
    const hostname = raw.includes("://") ? new URL(raw).hostname : raw.split("/")[0];
    const normalized = hostname.toLowerCase().replace(/^\.+|\.+$/g, "");
    if (!normalized || normalized.length > 253 || normalized.includes("..") || /[^a-z0-9.-]/.test(normalized)) return "";
    return normalized;
  } catch {
    return "";
  }
}

export function isTrustActive(entry, now = Date.now()) {
  if (!entry) return false;
  return entry.until === 0 || Number(entry.until) > now;
}
