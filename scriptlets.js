// Scriptlet engine (MAIN world).
//
// Injected into the page's own JavaScript context so scriptlets can neutralize
// page-side behaviors (anti-adblock bait, forced pop-ups, tracker bootstrappers)
// the way uBlock Origin / Ghostery scriptlets do. This runs in the MAIN world,
// so it has NO access to chrome.* APIs -- background.js registers/unregisters it
// based on the `scriptlets` setting.
//
// Design notes:
//   * Every scriptlet is wrapped in try/catch so one bad rule can never break the
//     page or the rest of the engine.
//   * RULES is deliberately conservative. Per-site scriptlet rules need testing on
//     live pages; add entries here (or via a future remote-rules channel) once
//     verified. This ships the capability, not a large untested rule set.
//   * No YouTube anti-adblock-detection scriptlets are included by design.
(() => {
  "use strict";
  const host = location.hostname.toLowerCase();

  const matchesDomain = (pattern) =>
    pattern === "*" || host === pattern || host.endsWith(`.${pattern}`);

  // Resolve a dotted chain like "a.b.c" to { owner, key }, creating nothing.
  const resolveChain = (root, chain) => {
    const parts = String(chain).split(".");
    let owner = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      if (owner == null) return null;
      owner = owner[parts[i]];
    }
    return owner == null ? null : { owner, key: parts[parts.length - 1] };
  };

  const coerce = (value) => {
    if (value === "true") return true;
    if (value === "false") return false;
    if (value === "null") return null;
    if (value === "undefined") return undefined;
    if (value === "noopFunc") return function () {};
    if (value === "trueFunc") return function () { return true; };
    if (value === "falseFunc") return function () { return false; };
    if (value === "emptyArr") return [];
    if (value === "emptyObj") return {};
    if (value === "" ) return "";
    if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
    return value;
  };

  // --- scriptlet library ---------------------------------------------------
  const SCRIPTLETS = {
    // Define window.<chain> as a non-writable constant. Defeats simple
    // "if (adblockDetected) ..." flags without touching real page logic.
    "set-constant"(chain, rawValue) {
      const target = resolveChain(window, chain);
      const value = coerce(rawValue);
      const define = (obj, key) => {
        try {
          Object.defineProperty(obj, key, {
            configurable: false,
            get: () => value,
            set: () => {}
          });
        } catch {}
      };
      if (target) define(target.owner, target.key);
    },

    // Throw a benign reference error when a bait property is READ.
    "abort-on-property-read"(chain) {
      const target = resolveChain(window, chain);
      if (!target) return;
      const err = () => { throw new ReferenceError(`${chain} (blocked)`); };
      try {
        Object.defineProperty(target.owner, target.key, {
          configurable: false,
          get: err,
          set: () => {}
        });
      } catch {}
    },

    // Throw when a bait property is WRITTEN (e.g. a detector reassigning a hook).
    "abort-on-property-write"(chain) {
      const target = resolveChain(window, chain);
      if (!target) return;
      try {
        let stored = target.owner[target.key];
        Object.defineProperty(target.owner, target.key, {
          configurable: false,
          get: () => stored,
          set: () => { throw new ReferenceError(`${chain} (blocked)`); }
        });
        void stored;
      } catch {}
    },

    // Replace a function with a no-op.
    "no-op"(chain) {
      const target = resolveChain(window, chain);
      if (target) {
        try { target.owner[target.key] = function () {}; } catch {}
      }
    },

    // Periodically strip attributes (e.g. right-click / copy blockers) from
    // elements matching a selector. Reversible and low-risk.
    "remove-attr"(attrs, selector) {
      const attrList = String(attrs).split(/\s*\|\s*/).filter(Boolean);
      const sel = selector || "*";
      const run = () => {
        try {
          for (const el of document.querySelectorAll(sel)) {
            for (const a of attrList) if (el.hasAttribute(a)) el.removeAttribute(a);
          }
        } catch {}
      };
      run();
      try {
        const mo = new MutationObserver(run);
        const start = () => mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
        if (document.documentElement) start();
        else document.addEventListener("DOMContentLoaded", start, { once: true });
      } catch {}
    }
  };

  const apply = (name, args) => {
    const fn = SCRIPTLETS[name];
    if (typeof fn !== "function") return;
    try { fn(...args); } catch {}
  };

  // --- rules (conservative default set) ------------------------------------
  // Each rule: { domains: [...], scriptlet: "name", args: [...] }.
  // Add verified per-site rules below. Kept intentionally small.
  const RULES = [
    // Neutralize common right-click / text-selection blockers site-wide.
    // Safe and reversible: only strips oncontextmenu / onselectstart handlers.
    { domains: ["*"], scriptlet: "remove-attr", args: ["oncontextmenu|onselectstart|oncopy", "body,div,article,section,main"] }
  ];

  for (const rule of RULES) {
    if (!Array.isArray(rule.domains) || !rule.domains.some(matchesDomain)) continue;
    apply(rule.scriptlet, rule.args || []);
  }
})();
