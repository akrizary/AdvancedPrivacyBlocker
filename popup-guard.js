// Popunder / click-hijack guard (MAIN world).
//
// Many ad-supported sites attach a document-wide click listener that calls
// window.open() on an unrelated click ("click anywhere, get an ad tab"), usually
// throttled so it fires only occasionally. Because the script is often served
// first-party, declarativeNetRequest cannot stop it -- the call has to be
// intercepted in the page's own JavaScript context.
//
// Policy: window.open() is allowed when it plausibly reflects the user's intent,
// and blocked otherwise:
//   * same-site targets                                  -> allow
//   * target matches an anchor the user just clicked      -> allow
//   * known sign-in / payment providers                   -> allow
//   * about:blank / no URL                                -> allow (too many
//     legitimate uses; a blocked stub would break print and preview flows)
//   * anything else cross-site                            -> blocked, stub returned
//
// background.js registers this only while the `popupGuard` setting is on, so the
// user has a single switch if a legitimate popup is ever refused.
(() => {
  "use strict";
  if (window.__abPopupGuard) return;
  window.__abPopupGuard = true;

  const MULTI_PART_SUFFIXES = new Set([
    "co.uk", "org.uk", "com.au", "com.br", "co.jp", "com.my", "com.sg", "co.nz", "co.in"
  ]);

  // Approximate eTLD+1 so subdomains of the current site count as same-site.
  const registrable = (host) => {
    const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const tail2 = parts.slice(-2).join(".");
    return MULTI_PART_SUFFIXES.has(tail2) ? parts.slice(-3).join(".") : tail2;
  };

  // Cross-origin popups that are normally genuine.
  const ALLOWED_PROVIDERS = [
    "accounts.google.com", "appleid.apple.com", "login.microsoftonline.com",
    "login.live.com", "login.yahoo.com", "facebook.com", "x.com", "twitter.com",
    "github.com", "gitlab.com", "linkedin.com", "discord.com", "slack.com",
    "paypal.com", "stripe.com", "checkout.stripe.com", "braintreegateway.com",
    "adyen.com", "razorpay.com", "midtrans.com", "billplz.com", "toyyibpay.com",
    "recaptcha.net", "google.com", "gstatic.com", "duitnow.com.my"
  ];
  const isProvider = (host) =>
    ALLOWED_PROVIDERS.some(provider => host === provider || host.endsWith(`.${provider}`));

  // Remember the most recent anchor the user actually clicked.
  let lastAnchorAt = 0;
  let lastAnchorHost = "";
  document.addEventListener("click", (event) => {
    const anchor = event.target?.closest?.("a[href]");
    if (!anchor) { lastAnchorAt = 0; lastAnchorHost = ""; return; }
    lastAnchorAt = Date.now();
    try { lastAnchorHost = new URL(anchor.href, location.href).hostname.toLowerCase(); }
    catch { lastAnchorHost = ""; }
  }, true);

  // A window-like stub so callers doing w.focus()/w.close() do not throw.
  const makeStub = () => {
    const noop = () => {};
    const stub = {
      closed: true, opener: null, name: "", status: "",
      focus: noop, blur: noop, close: noop, print: noop,
      postMessage: noop, moveTo: noop, resizeTo: noop, scrollTo: noop,
      alert: noop, confirm: () => false, prompt: () => null,
      document: { write: noop, writeln: noop, open: noop, close: noop, body: null }
    };
    stub.window = stub;
    stub.self = stub;
    stub.top = stub;
    return stub;
  };

  const nativeOpen = window.open;

  function guardedOpen(url, ...rest) {
    try {
      // No URL / about:blank: allow, since legitimate print and preview flows
      // open a blank window and write into it.
      const raw = url === undefined || url === null ? "" : String(url);
      if (!raw || /^about:blank$/i.test(raw.trim())) {
        return nativeOpen.apply(window, [url, ...rest]);
      }

      const target = new URL(raw, location.href);
      if (!/^https?:$/.test(target.protocol)) {
        return nativeOpen.apply(window, [url, ...rest]);
      }

      const targetHost = target.hostname.toLowerCase();
      const sameSite = registrable(targetHost) === registrable(location.hostname);
      const fromAnchor = Date.now() - lastAnchorAt < 1500
        && lastAnchorHost !== "" && registrable(targetHost) === registrable(lastAnchorHost);

      if (sameSite || fromAnchor || isProvider(targetHost)) {
        return nativeOpen.apply(window, [url, ...rest]);
      }

      console.info("[Advanced Privacy Blocker] blocked popunder window.open:", target.href);
      window.dispatchEvent(new CustomEvent("advanced-blocker-popup-blocked", {
        detail: { url: target.href }
      }));
      return makeStub();
    } catch {
      // Never let the guard break the page: fall through to native behaviour.
      try { return nativeOpen.apply(window, [url, ...rest]); } catch { return null; }
    }
  }

  try {
    Object.defineProperty(window, "open", {
      configurable: true, writable: true, value: guardedOpen
    });
  } catch {
    try { window.open = guardedOpen; } catch {}
  }
})();
