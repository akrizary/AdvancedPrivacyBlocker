(async () => {
  const tools = globalThis.ABContentTools;
  if (!tools || !/^https?:$/.test(location.protocol)) return;

  const host = location.hostname.toLowerCase();
  let config;
  try {
    config = await chrome.runtime.sendMessage({ type: "getContentConfig", host });
  } catch {
    return;
  }
  if (!config || !config.enabled) return;

  const settings = config.settings || {};
  const counters = { cleanedLinks: 0, consentActions: 0, zapped: 0 };
  const injectedStyles = new Map();

  function selectorSupported(selector) {
    if (!selector || selector.length > 1200 || /[{}]/.test(selector)) return false;
    try {
      if (globalThis.CSS?.supports) return CSS.supports(`selector(${selector})`);
      document.querySelector(selector);
      return true;
    } catch {
      return false;
    }
  }

  function injectSelectors(id, selectors) {
    const unique = [...new Set((selectors || []).filter(selectorSupported))].slice(0, 5000);
    if (!unique.length) return;
    let style = injectedStyles.get(id) || document.getElementById(id);
    if (!style) {
      style = document.createElement("style");
      style.id = id;
      (document.head || document.documentElement).appendChild(style);
      injectedStyles.set(id, style);
    }
    style.textContent = unique.map(s => `${s}{display:none!important;visibility:hidden!important;}`).join("\n");
  }

  function distractionSelectors() {
    const selectors = [];
    if (settings.socialWidgets) selectors.push(
      ".fb-like", ".fb-share-button", ".twitter-share-button", ".linkedin-share-button",
      "iframe[src*='facebook.com/plugins']", "iframe[src*='platform.twitter.com/widgets']",
      "iframe[src*='platform.linkedin.com']", "[class*='social-share']", "[id*='social-share']"
    );
    if (settings.signInPrompts) selectors.push(
      "#credential_picker_container", "#credential_picker_iframe", "iframe[src*='accounts.google.com/gsi']",
      "[id*='google-one-tap']", "[class*='google-one-tap']"
    );
    if (settings.appBanners) selectors.push(
      "[class*='smart-app-banner']", "[id*='smart-app-banner']", "[class*='app-download-banner']",
      "[id*='app-download-banner']", "[class*='open-in-app']", "[id*='open-in-app']"
    );
    if (settings.youtubeShorts && host.endsWith("youtube.com")) selectors.push(
      "ytd-reel-shelf-renderer", "ytd-rich-section-renderer:has(a[href^='/shorts/'])",
      "ytd-guide-entry-renderer:has(a[href^='/shorts'])", "a[href^='/shorts/']"
    );
    if (settings.socialReels) selectors.push(
      "a[href*='/reels/']", "a[href*='/reel/']", "a[href*='/shorts/']",
      "[aria-label*='Reels']", "[aria-label*='Shorts']"
    );
    return selectors;
  }

  injectSelectors("advanced-blocker-cosmetic", config.selectors || []);
  injectSelectors("advanced-blocker-custom", config.customSelectors || []);
  injectSelectors("advanced-blocker-distractions", distractionSelectors());

  let activityTimer = null;
  function reportActivity(patch = {}) {
    Object.assign(counters, patch);
    clearTimeout(activityTimer);
    activityTimer = setTimeout(() => {
      chrome.runtime.sendMessage({ type: "contentActivity", host, counters: { ...counters } }).catch(() => {});
    }, 350);
  }

  function cleanAnchor(anchor) {
    if (!(anchor instanceof HTMLAnchorElement) || !anchor.href) return false;
    if (anchor.hasAttribute("download")) return false;
    const result = tools.sanitizeUrl(anchor.href, location.href);
    if (!result.changed || !/^https?:/i.test(result.url)) return false;
    anchor.href = result.url;
    anchor.dataset.advancedBlockerCleaned = result.reason;
    counters.cleanedLinks += 1;
    return true;
  }

  function cleanLinks(root = document) {
    if (!(settings.redirectProtection || settings.stripTrackingParams)) return 0;
    const links = root.querySelectorAll ? root.querySelectorAll("a[href]") : [];
    let changed = 0;
    for (const link of links) if (cleanAnchor(link)) changed += 1;
    if (changed) reportActivity();
    return changed;
  }

  cleanLinks();
  document.addEventListener("click", event => {
    if (!(settings.redirectProtection || settings.stripTrackingParams)) return;
    const anchor = event.target?.closest?.("a[href]");
    if (anchor && cleanAnchor(anchor)) reportActivity();
  }, true);

  const linkObserver = new MutationObserver(records => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches?.("a[href]")) cleanAnchor(node);
        cleanLinks(node);
      }
    }
  });
  if (document.documentElement) linkObserver.observe(document.documentElement, { childList: true, subtree: true });

  const resourceQueue = new Set();
  let resourceTimer = null;
  function flushResources() {
    resourceTimer = null;
    const urls = [...resourceQueue].slice(0, 200);
    resourceQueue.clear();
    if (!urls.length) return;
    chrome.runtime.sendMessage({
      type: "observeResources",
      sourceUrl: location.href,
      urls
    }).catch(() => {});
  }
  function queueResource(url) {
    if (!settings.antiTracking || !/^https?:/i.test(url)) return;
    resourceQueue.add(url);
    if (!resourceTimer) resourceTimer = setTimeout(flushResources, 800);
  }

  try {
    for (const entry of performance.getEntriesByType("resource")) queueResource(entry.name);
    const perfObserver = new PerformanceObserver(list => {
      for (const entry of list.getEntries()) queueResource(entry.name);
    });
    perfObserver.observe({ type: "resource", buffered: true });
  } catch {}

  const KNOWN_REJECT_SELECTORS = [
    "#onetrust-reject-all-handler", "#CybotCookiebotDialogBodyButtonDecline",
    "#CybotCookiebotDialogBodyLevelButtonLevelOptinDeclineAll",
    "#didomi-notice-disagree-button", "button.didomi-dismiss-button",
    ".qc-cmp2-summary-buttons button[mode='secondary']",
    ".qc-cmp2-footer button[mode='secondary']", ".cmplz-deny", ".cky-btn-reject",
    ".osano-cm-denyAll", ".iubenda-cs-reject-btn", "button[data-testid='uc-deny-all-button']",
    ".termly-styles-button-secondary", "#truste-consent-required",
    ".sp_choice_type_REJECT_ALL", "button[title='Reject All']",
    ".fc-cta-do-not-consent", ".fc-button.fc-data-preferences-accept-all + button",
    ".cc-nb-reject", ".klaro .cn-decline", ".cm-btn-danger", ".cookie-consent__reject",
    "button[aria-label*='Reject All' i]", "button[title*='Reject All' i]",
    "button[aria-label*='Reject non-essential' i]", "button[aria-label*='Decline optional' i]",
    "button[data-action='reject-all']", "button[data-testid*='reject-all']",
    "button[data-cy*='reject']", "button[data-role*='reject']"
  ];
  const CONSENT_ROOTS = [
    "#onetrust-banner-sdk", "#CybotCookiebotDialog", "#didomi-host", ".qc-cmp2-container",
    ".cmplz-cookiebanner", ".cky-consent-container", ".osano-cm-window", ".iubenda-cs-container",
    "#truste-consent-track", ".termly-consent-banner", ".sp-message-container",
    ".fc-consent-root", ".klaro .cookie-notice", ".cc-window", "#usercentrics-root",
    "[id*='cookie'][role='dialog' i]", "[class*='cookie'][role='dialog' i]",
    "[id*='consent'][role='dialog' i]", "[class*='consent'][role='dialog' i]",
    "[id*='gdpr'][role='dialog' i]", "[class*='gdpr'][role='dialog' i]",
    "[aria-label*='cookie' i]", "[aria-label*='consent' i]", "[aria-modal='true'][class*='consent' i]"
  ];
  const REJECT_TEXT = [
    /^reject all$/i, /^reject$/i, /^decline all$/i, /^deny all$/i, /^decline$/i,
    /^reject non-essential$/i, /^reject optional$/i, /^decline optional$/i,
    /^only necessary$/i, /^necessary only$/i, /^essential only$/i, /^accept only essential$/i,
    /^continue without accepting$/i, /^do not accept$/i, /^use necessary cookies only$/i,
    /^manage.*reject$/i, /^reject additional$/i, /^disagree and close$/i, /^disagree$/i,
    /^tolak semua$/i, /^tolak$/i, /^hanya kuki perlu$/i, /^hanya yang perlu$/i,
    /^tidak setuju$/i, /^jangan terima$/i, /^refuse all$/i, /^tout refuser$/i,
    /^alle ablehnen$/i, /^rechazar todo$/i, /^rifiuta tutto$/i, /^recusar tudo$/i,
    /^weiger alles$/i, /^avvisa alla$/i, /^afvis alle$/i, /^odrzuć wszystko$/i,
    /^tümünü reddet$/i, /^avslå alle$/i, /^hylkää kaikki$/i, /^すべて拒否$/i,
    /^모두 거부$/i, /^全部拒绝$/i, /^拒绝所有$/i, /^отклонить все$/i
  ];

  function looksLikeConsentRoot(node) {
    if (!(node instanceof Element)) return false;
    const text = (node.textContent || "").replace(/\s+/g, " ").trim().slice(0, 1200);
    return /cookie|consent|privacy preferences|personal data|kuki|persetujuan|privasi/i.test(text);
  }

  function findRejectButton(root) {
    for (const selector of KNOWN_REJECT_SELECTORS) {
      const button = root.querySelector?.(selector) || (root.matches?.(selector) ? root : null);
      if (button && button.getClientRects().length) return button;
    }
    const controls = root.querySelectorAll?.("button, [role='button'], input[type='button'], input[type='submit']") || [];
    for (const control of controls) {
      const text = (control.innerText || control.value || control.getAttribute("aria-label") || "")
        .replace(/\s+/g, " ").trim();
      if (REJECT_TEXT.some(pattern => pattern.test(text)) && control.getClientRects().length) return control;
    }
    return null;
  }

  const handledConsentRoots = new WeakSet();
  function runNeverConsent() {
    if (!settings.neverConsent) return false;
    let acted = false;
    const roots = new Set();
    for (const selector of CONSENT_ROOTS) {
      for (const root of document.querySelectorAll(selector)) roots.add(root);
    }
    for (const dialog of document.querySelectorAll("[role='dialog']")) {
      if (looksLikeConsentRoot(dialog)) roots.add(dialog);
    }

    for (const root of roots) {
      if (handledConsentRoots.has(root) || !looksLikeConsentRoot(root)) continue;
      const reject = findRejectButton(root);
      if (reject && settings.consentMode !== "hide") {
        handledConsentRoots.add(root);
        try {
          reject.click();
          counters.consentActions += 1;
          acted = true;
        } catch {}
      } else if (settings.consentMode === "hide") {
        handledConsentRoots.add(root);
        root.style.setProperty("display", "none", "important");
        document.documentElement.style.removeProperty("overflow");
        document.body?.style.removeProperty("overflow");
        counters.consentActions += 1;
        acted = true;
      }
    }
    if (acted) reportActivity();
    return acted;
  }

  if (settings.neverConsent) {
    [50, 350, 1000, 2500, 5000].forEach(delay => setTimeout(runNeverConsent, delay));
    let consentTimer = null;
    const consentObserver = new MutationObserver(() => {
      clearTimeout(consentTimer);
      consentTimer = setTimeout(runNeverConsent, 180);
    });
    if (document.documentElement) consentObserver.observe(document.documentElement, { childList: true, subtree: true });
  }

  function isSearchPage() {
    return /(^|\.)google\./.test(host) || host.endsWith("bing.com") || host.endsWith("duckduckgo.com") || host.endsWith("brave.com");
  }

  async function annotateSearchResults() {
    if (!settings.serpProtection || !isSearchPage()) return;
    const anchors = [...document.querySelectorAll("a[href]")]
      .filter(a => !a.dataset.abSerpChecked && /^https?:/i.test(a.href))
      .slice(0, 60);
    if (!anchors.length) return;
    anchors.forEach(a => { a.dataset.abSerpChecked = "1"; });
    const urls = anchors.map(a => tools.sanitizeUrl(a.href, location.href).url);
    let result;
    try { result = await chrome.runtime.sendMessage({ type: "classifyDestinations", urls }); }
    catch { return; }
    const matches = result?.matches || [];
    anchors.forEach((anchor, index) => {
      const match = matches[index];
      if (!match || anchor.querySelector?.(".advanced-blocker-serp-badge")) return;
      const badge = document.createElement("span");
      badge.className = "advanced-blocker-serp-badge";
      badge.textContent = `${match.categoryName}: ${match.organization}`;
      badge.title = `${match.name} — recognized destination or redirect service`;
      badge.style.cssText = "display:inline-block;margin-left:6px;padding:1px 5px;border:1px solid #8aa4c8;border-radius:9px;font:10px/1.4 system-ui;color:#335b8e;background:#eef5ff;vertical-align:middle";
      anchor.appendChild(badge);
    });
  }
  if (settings.serpProtection && isSearchPage()) {
    setTimeout(annotateSearchResults, 300);
    setTimeout(annotateSearchResults, 1200);
    let serpTimer = null;
    const serpObserver = new MutationObserver(() => {
      clearTimeout(serpTimer);
      serpTimer = setTimeout(annotateSearchResults, 250);
    });
    if (document.documentElement) serpObserver.observe(document.documentElement, { childList: true, subtree: true });
  }

  function cssEscape(value) {
    if (globalThis.CSS?.escape) return CSS.escape(value);
    return String(value).replace(/[^a-zA-Z0-9_-]/g, c => `\\${c}`);
  }

  function uniqueSelector(element) {
    if (!(element instanceof Element)) return "";
    if (element.id && document.querySelectorAll(`#${cssEscape(element.id)}`).length === 1) {
      return `#${cssEscape(element.id)}`;
    }
    const parts = [];
    let node = element;
    for (let depth = 0; node && node !== document.documentElement && depth < 5; depth += 1) {
      let part = node.localName || "div";
      const classes = [...node.classList].filter(c => c.length < 50 && !/[0-9a-f]{8,}/i.test(c)).slice(0, 3);
      if (classes.length) part += classes.map(c => `.${cssEscape(c)}`).join("");
      const siblings = node.parentElement ? [...node.parentElement.children].filter(x => x.localName === node.localName) : [];
      if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(node) + 1})`;
      parts.unshift(part);
      const candidate = parts.join(" > ");
      try { if (document.querySelectorAll(candidate).length === 1) return candidate; } catch {}
      node = node.parentElement;
    }
    return parts.join(" > ");
  }

  let zapperActive = false;
  function startZapper() {
    if (zapperActive || !document.documentElement) return false;
    zapperActive = true;
    const style = document.createElement("style");
    style.id = "advanced-blocker-zapper-style";
    style.textContent = ".advanced-blocker-zap-hover{outline:3px solid #d93025!important;outline-offset:2px!important;cursor:crosshair!important}";
    document.documentElement.appendChild(style);
    let hovered = null;

    const onMove = event => {
      if (hovered) hovered.classList.remove("advanced-blocker-zap-hover");
      hovered = event.target;
      hovered?.classList?.add("advanced-blocker-zap-hover");
    };
    const cleanup = () => {
      zapperActive = false;
      hovered?.classList?.remove("advanced-blocker-zap-hover");
      style.remove();
      document.removeEventListener("mouseover", onMove, true);
      document.removeEventListener("click", onClick, true);
      document.removeEventListener("keydown", onKey, true);
    };
    const onKey = event => { if (event.key === "Escape") cleanup(); };
    const onClick = async event => {
      event.preventDefault();
      event.stopImmediatePropagation();
      const target = event.target;
      if (!(target instanceof Element) || target === document.documentElement || target === document.body) {
        cleanup();
        return;
      }
      const selector = uniqueSelector(target);
      cleanup();
      if (!selector) return;
      target.style.setProperty("display", "none", "important");
      counters.zapped += 1;
      reportActivity();
      try { await chrome.runtime.sendMessage({ type: "addCustomCosmetic", host, selector }); } catch {}
    };

    document.addEventListener("mouseover", onMove, true);
    document.addEventListener("click", onClick, true);
    document.addEventListener("keydown", onKey, true);
    return true;
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "startZapper") {
      startZapper();
      sendResponse({ ok: true });
    }
  });
})();
