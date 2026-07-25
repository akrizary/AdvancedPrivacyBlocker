(() => {
  const NAVIGATION_TRACKING_PARAMS = new Set([
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "gclid", "dclid", "gbraid", "wbraid", "fbclid", "msclkid", "twclid", "ttclid",
    "li_fat_id", "igshid", "mc_cid", "mc_eid", "mkt_tok", "vero_conv", "vero_id",
    "oly_anon_id", "oly_enc_id", "rb_clickid", "wickedid", "epik", "irclickid",
    "_hsenc", "_hsmi", "hsctatracking", "s_cid", "yclid", "gad_source", "gad_campaignid"
  ]);
  const TRACKING_PARAMS = new Set([
    ...NAVIGATION_TRACKING_PARAMS,
    "scid", "spm", "ref_src", "ref_url", "campaignid", "adgroupid", "adid"
  ]);

  function safeDecode(value) {
    try { return decodeURIComponent(value); } catch { return value; }
  }

  function decodeBing(value) {
    if (!value) return "";
    let raw = value;
    if (raw.startsWith("a1")) raw = raw.slice(2);
    raw = raw.replace(/-/g, "+").replace(/_/g, "/");
    while (raw.length % 4) raw += "=";
    try { return atob(raw); } catch { return ""; }
  }

  function unwrapRedirect(url) {
    const host = url.hostname.toLowerCase();
    const path = url.pathname;
    const candidates = [];

    if ((host === "www.google.com" || host.endsWith(".google.com")) && path === "/url") {
      candidates.push(url.searchParams.get("q"), url.searchParams.get("url"));
    }
    if ((host === "www.google.com" || host.endsWith(".google.com")) && path === "/imgres") {
      candidates.push(url.searchParams.get("imgurl"));
    }
    if (host === "l.facebook.com" || host === "lm.facebook.com") candidates.push(url.searchParams.get("u"));
    if (host === "www.linkedin.com" && path.includes("/safety/go")) candidates.push(url.searchParams.get("url"));
    if (host.endsWith("duckduckgo.com") && path.startsWith("/l/")) candidates.push(url.searchParams.get("uddg"));
    if (host.endsWith("bing.com") && path === "/ck/a") candidates.push(decodeBing(url.searchParams.get("u")));
    if (host === "out.reddit.com") candidates.push(url.searchParams.get("url"));

    for (const candidate of candidates) {
      if (!candidate) continue;
      try {
        const parsed = new URL(safeDecode(candidate));
        if (parsed.protocol === "http:" || parsed.protocol === "https:") return parsed;
      } catch {}
    }
    return url;
  }

  // Mirror of registrableApprox in lib/domain-utils.js. Kept inline because this
  // file runs as a classic content script and cannot import ES modules. Keep the
  // logic and suffix list in sync with domain-utils.js.
  function registrableApprox(host) {
    const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const multiPartSuffixes = new Set(["co.uk", "org.uk", "com.au", "com.br", "co.jp", "com.my", "com.sg", "co.nz", "co.in"]);
    const tail2 = parts.slice(-2).join(".");
    return multiPartSuffixes.has(tail2) ? parts.slice(-3).join(".") : tail2;
  }

  function cleanParams(url, sourceUrl) {
    let changed = false;
    let crossSite = true;
    try {
      const source = new URL(sourceUrl);
      crossSite = registrableApprox(source.hostname) !== registrableApprox(url.hostname);
    } catch {}
    const allowed = crossSite ? TRACKING_PARAMS : NAVIGATION_TRACKING_PARAMS;
    for (const key of [...url.searchParams.keys()]) {
      const lower = key.toLowerCase();
      if (lower.startsWith("utm_") || allowed.has(lower)) {
        url.searchParams.delete(key);
        changed = true;
      }
    }
    return changed;
  }

  function sanitizeUrl(value, base = location.href) {
    try {
      const original = new URL(value, base);
      if (!/^https?:$/.test(original.protocol)) return { url: original.href, changed: false, reason: "unsupported" };
      const unwrapped = unwrapRedirect(new URL(original.href));
      const unwrappedChanged = unwrapped.href !== original.href;
      const paramsChanged = cleanParams(unwrapped, base);
      return {
        url: unwrapped.href,
        changed: unwrappedChanged || paramsChanged,
        reason: unwrappedChanged ? "redirect" : (paramsChanged ? "parameters" : "none")
      };
    } catch {
      return { url: String(value || ""), changed: false, reason: "invalid" };
    }
  }

  function domainMatches(host, domain) {
    const h = String(host || "").toLowerCase();
    const d = String(domain || "").toLowerCase();
    return h === d || h.endsWith(`.${d}`);
  }

  globalThis.ABContentTools = Object.freeze({
    sanitizeUrl, domainMatches, TRACKING_PARAMS, NAVIGATION_TRACKING_PARAMS
  });
})();
