// ClickFix / fake-CAPTCHA clipboard guard (MAIN world).
//
// THE ATTACK
// ----------
// "ClickFix" is, as of 2026, the most common browser-delivered initial-access
// technique in the wild (Microsoft's Digital Defense Report put it at 47% of
// observed attacks; Push Security measured 52% of their detections in Q2 2026).
// Roughly four in five payloads arrive through search engines, compromised sites,
// malvertising or SEO poisoning -- i.e. the same ad supply chain this extension
// already filters -- which is why the network layer alone cannot be the answer.
//
// The mechanism is deliberately simple and needs no exploit:
//   1. A page imitates a Cloudflare Turnstile / reCAPTCHA check ("Verify you are
//      human"), or a fake "fix this error" dialog.
//   2. The PAGE writes an OS command to the clipboard -- navigator.clipboard
//      .writeText(), or a hijacked `copy` event, or execCommand("copy").
//   3. The page instructs the user to press Win+R (or open Terminal) and paste.
//      The payload usually ends in a comment such as
//      `# ✅ "I am not a robot - reCAPTCHA Verification ID: 7f3a..."` so that what
//      lands in the Run box still looks like a verification token.
//   4. The user executes it themselves. No sandbox is escaped; the browser is
//      only the delivery vehicle, so nothing in DNR or CSP can intervene.
//
// Variants seen since: a DNS-based one that runs `nslookup -q=txt` against an
// attacker-controlled resolver to fetch the real payload (defeats URL blocking),
// and "browser cache smuggling", which pre-fetches a script into the HTTP cache
// disguised as a PNG. Both still depend on step 2, which is the one step that
// happens in JavaScript -- and therefore the one place a content script can act.
//
// WHY HERE
// --------
// This is the same shape as popup-guard.js: a page-side capability that cannot be
// filtered by URL, so it is wrapped in the page's own context instead. The guard
// hooks only the clipboard write paths and is otherwise inert.
//
// LIMITS -- be honest about these:
//   * A user who types the command manually from an image is unreachable.
//   * Pages can read instructions aloud, use an extension-free browser profile, or
//     move to a native dialog. This closes the common automated path, not the idea.
//   * The guard sees a string, not intent. The whole difficulty is that
//     `irm get.scoop.sh | iex` is a real install command on scoop.sh and a textbook
//     payload anywhere else -- which is why the decision below is a policy choice,
//     not a detection problem.
//   * Cross-realm reach depends on the browser injecting this script into
//     page-created frames. `matchOriginAsFallback: true` on the registration is the
//     platform mechanism for that and covers about:blank, about:srcdoc and blob:
//     frames at document_start. A security review suggested going further and
//     patching each new frame's prototypes from the top realm, by hooking the
//     `contentWindow`/`contentDocument` getters on HTMLIFrameElement.prototype.
//     That is deliberately NOT done: reaching into another realm's intrinsics on
//     every frame access is far more likely to break ordinary pages than to catch
//     an attack, it is still racy, and it duplicates what the injection already
//     guarantees. The residual risk is a realm the browser declines to inject
//     into, where this guard simply does not run -- which is the same boundary
//     every other MAIN-world guard here has.
//
// background.js registers this only while the `clickfixGuard` setting is on.
(() => {
  "use strict";
  if (window.__abClickfixGuard) return;
  window.__abClickfixGuard = true;

  // --- captured intrinsics -------------------------------------------------
  // Everything below runs at document_start, before any page script, and every
  // intrinsic the guard depends on is captured here. Nothing after this point
  // may look an intrinsic up by name at call time.
  //
  // This is the generalisation of four separate bypasses found in this file: the
  // guard's own tooling is page-controlled unless it is captured first. Concrete
  // instances, all of which defeat the whole guard rather than one path:
  //
  //   Function.prototype.call - every wrapper forwards with native.call(this, v).
  //     Replacing it routes all of them through page code.
  //   String - `const value = String(text)` is the single-coercion fix; a replaced
  //     String can return an OBJECT, which the classifier stringifies to something
  //     benign while the WebIDL binding coerces it again to the payload.
  //   Object.defineProperty - sealSequence uses it to lock an iterator. A no-op
  //     replacement does not throw, so the seal silently fails and the array is
  //     forwarded with a prototype-resolved iterator.
  //   Promise.resolve - returned to callers on a block.
  //
  // Symbol.iterator deliberately is NOT captured: it is defined as
  // { writable: false, enumerable: false, configurable: false } on Symbol, so it
  // cannot be replaced and capturing it would only suggest otherwise.
  const nativeApply = Reflect.apply;
  const nativeDefineProperty = Object.defineProperty;
  const nativeGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const nativeGetPrototypeOf = Object.getPrototypeOf;
  const nativeFreeze = Object.freeze;
  const nativeKeys = Object.keys;
  const nativeString = String;
  const nativePromiseResolve = Promise.resolve.bind(Promise);
  const nativeIsArray = Array.isArray;
  const NativePromise = Promise;
  const nativeThen = Promise.prototype.then;
  const nativeRegExpTest = RegExp.prototype.test;
  const nativeToLowerCase = String.prototype.toLowerCase;
  const nativeSplit = String.prototype.split;
  const nativeStringSlice = String.prototype.slice;
  const nativeTrim = String.prototype.trim;
  const nativeArrayJoin = Array.prototype.join;
  const nativeIncludes = Array.prototype.includes;
  const nativeArrayFrom = Array.from;
  const nativeDateNow = Date.now;
  const NativeCustomEvent = typeof CustomEvent === "function" ? CustomEvent : null;

  // DOM accessors the guard reads page-reachable data through. Reading them by
  // property name classifies what the page offers rather than what the browser
  // will copy: an own `value` defined on a focused input shadows the real getter
  // for us while the browser still copies the selection from internal slots.
  const grabGetter = (holder, name) => {
    try { return holder ? nativeGetOwnPropertyDescriptor(holder, name)?.get || null : null; }
    catch { return null; }
  };
  const grabMethod = (holder, name) => {
    try {
      const fn = holder ? holder[name] : null;
      return typeof fn === "function" ? fn : null;
    } catch { return null; }
  };
  const protoOf = (name) => {
    try { return typeof window[name] === "function" ? window[name].prototype : null; }
    catch { return null; }
  };
  const nativeActiveElement = grabGetter(protoOf("Document"), "activeElement");
  const nativeDocGetSelection = grabMethod(protoOf("Document"), "getSelection");
  const nativeWinGetSelection = grabMethod(window, "getSelection");
  const nativeSelectionToString = grabMethod(protoOf("Selection"), "toString");
  const nativeInputValue = grabGetter(protoOf("HTMLInputElement"), "value");
  const nativeTextAreaValue = grabGetter(protoOf("HTMLTextAreaElement"), "value");
  const nativeGetAttribute = grabMethod(protoOf("Element"), "getAttribute");
  const nativeEventClipboardData = grabGetter(protoOf("ClipboardEvent"), "clipboardData");
  const nativeDTGetData = grabMethod(protoOf("DataTransfer"), "getData");

  // `await p` is NOT safe on a page-reachable promise. Per spec it performs
  // PromiseResolve(%Promise%, p), which does Get(p, "constructor") and only uses
  // p's internal slots when that is the intrinsic %Promise%. A page that replaces
  // Promise.prototype.constructor makes the check fail, so p is treated as a
  // thenable and Get(p, "then") - also page-replaceable - decides the resolution
  // value. The classifier would then inspect whatever the page chose while the
  // native call writes the item's real bytes. Every promise the guard consumes is
  // therefore driven through the captured `then` with explicit callbacks, and
  // composed inside promises built from the captured constructor.

  // Coerce to a primitive string using the captured String, and refuse anything
  // that does not come back as one. A value that will not reduce to a primitive
  // is exactly the shape used to smuggle a second coercion past the classifier,
  // so it is reported as a string that cannot be trusted rather than forwarded.
  const toPrimitiveString = (value) => {
    let out;
    try { out = nativeString(value == null ? "" : value); }
    catch { return null; }
    return typeof out === "string" ? out : null;
  };

  // --- payload shape -------------------------------------------------------
  // Tokens that make a string an OS command rather than text a page would
  // legitimately hand you. Grouped so the policy function can weigh them.

  // Interpreters and LOLBins used to execute or stage a payload.
  const EXECUTION_TOKENS = [
    /\bpowershell(\.exe)?\b/i, /\bpwsh(\.exe)?\b/i,
    /\bcmd(\.exe)?\s*\/[ck]\b/i, /\bconhost(\.exe)?\b/i,
    /\bmshta(\.exe)?\b/i, /\brundll32(\.exe)?\b/i, /\bregsvr32(\.exe)?\b/i,
    /\bcertutil\b/i, /\bbitsadmin\b/i, /\bmsiexec\b/i,
    /\bwscript\b/i, /\bcscript\b/i, /\bforfiles\b/i,
    /\bosascript\b/i, /\bcurl\b[^|]*\|\s*(ba)?sh\b/i, /\bwget\b[^|]*\|\s*(ba)?sh\b/i,
    /\/bin\/(ba|z)?sh\s+-c\b/i
  ];

  // Download-and-run composition: the actual intent of almost every payload.
  const DOWNLOAD_EXEC_TOKENS = [
    /\b(iex|invoke-expression)\b/i,
    /\|\s*iex\b/i,
    /\b(irm|iwr|invoke-webrequest|invoke-restmethod)\b/i,
    /\bdownloadstring\b/i, /\bdownloadfile\b/i,
    /\bfrombase64string\b/i,
    /\bnew-object\s+net\.webclient\b/i,
    /\bstart-process\b/i,
    /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}/i,   // base64-encoded command
    /\bnslookup\b[^\n]*-q(uery)?=txt\b/i,             // DNS-staged variant (2026)
    /\bcertutil\b[^\n]*-urlcache\b/i
  ];

  // Flags whose only purpose is to keep the window hidden or skip the profile.
  const STEALTH_TOKENS = [
    /-w(indowstyle)?\s+h(idden)?\b/i,
    /-nop(rofile)?\b/i,
    /-ep\s+bypass\b/i, /-executionpolicy\s+bypass\b/i,
    /-noni\b/i, /-noninteractive\b/i
  ];

  // The social-engineering wrapper: text appended so the pasted command still
  // reads as a verification token in the Run dialog.
  const LURE_TOKENS = [
    /✅|✔|🤖/,                     // check marks / robot emoji
    /#\s*[^\n]*\b(i am not a robot|not a robot|recaptcha|captcha|cloudflare|turnstile|verification|verify|human)\b/i,
    /\b(verification|session|ray)\s*id\s*[:=]/i
  ];

  // Walk by index with a captured RegExp.prototype.test. `patterns.reduce(...)`
  // and `re.test(...)` each resolve through a page-replaceable prototype, and
  // either one zeroes every token count on its own:
  //
  //   Array.prototype.reduce = () => 0
  //   RegExp.prototype.test = () => false
  //
  // With no command tokens counted, decide() returns "allow", so this was a
  // one-line total bypass of all four hook paths, not of one of them. Verified
  // against the real wrappers: the native received the full PowerShell payload.
  const countMatches = (text, patterns) => {
    let n = 0;
    for (let i = 0; i < patterns.length; i += 1) {
      let hit;
      // A pattern that will not run is treated as a match. Failing closed here
      // costs a false positive; failing open costs the whole guard.
      try { hit = nativeApply(nativeRegExpTest, patterns[i], [text]) === true; }
      catch { hit = true; }
      if (hit) n += 1;
    }
    return n;
  };

  const lowered = (value) => {
    try {
      const out = nativeApply(nativeToLowerCase, value, []);
      return typeof out === "string" ? out : value;
    } catch { return value; }
  };
  const trimmed = (value) => {
    try {
      const out = nativeApply(nativeTrim, value, []);
      return typeof out === "string" ? out : value;
    } catch { return value; }
  };
  const clipped = (value, end) => {
    try {
      const out = nativeApply(nativeStringSlice, value, [0, end]);
      return typeof out === "string" ? out : "";
    } catch { return ""; }
  };
  const countLines = (value) => {
    try {
      const parts = nativeApply(nativeSplit, value, ["\n"]);
      return nativeIsArray(parts) ? parts.length : 1;
    } catch { return 1; }
  };

  // The selection the browser would actually copy, read through captured natives.
  const readSelection = () => {
    try {
      let sel = null;
      if (nativeDocGetSelection) sel = nativeApply(nativeDocGetSelection, document, []);
      else if (nativeWinGetSelection) sel = nativeApply(nativeWinGetSelection, window, []);
      else if (typeof window.getSelection === "function") sel = window.getSelection();
      if (sel == null) return "";
      const text = nativeSelectionToString ? nativeApply(nativeSelectionToString, sel, []) : sel;
      return toPrimitiveString(text) || "";
    } catch { return ""; }
  };

  // A structured description of the payload, so policy reads as policy.
  function describe(text) {
    const value = toPrimitiveString(text);
    if (value === null) {
      // Unreducible to a primitive: treat as maximally suspicious rather than
      // letting it through unclassified.
      return { text: "[unreducible value]", length: 0, lines: 1,
               execution: 1, downloadExec: 1, stealth: 1, lure: 1 };
    }
    return {
      text: value,
      length: value.length,
      lines: countLines(value),
      execution: countMatches(value, EXECUTION_TOKENS),
      downloadExec: countMatches(value, DOWNLOAD_EXEC_TOKENS),
      stealth: countMatches(value, STEALTH_TOKENS),
      lure: countMatches(value, LURE_TOKENS)
    };
  }

  // --- user-intent context -------------------------------------------------
  // Was this write plausibly the user pressing a real "Copy" button? Tracked the
  // same way popup-guard.js tracks the last clicked anchor.
  let lastClickAt = 0;
  let lastClickLooksLikeCopy = false;

  const COPY_HINT = /\b(copy|copied|clipboard|duplicate|salin)\b/i;

  document.addEventListener("click", (event) => {
    // Only real input counts. `document.dispatchEvent(new MouseEvent("click"))`
    // is free for the page to call, so without this check a payload could
    // manufacture a "user gesture" and turn its own block into a mere warning --
    // defeating one of the three block conditions in decide().
    if (!event.isTrusted) return;
    lastClickAt = nativeDateNow();
    lastClickLooksLikeCopy = false;
    try {
      const el = event.target?.closest?.("button,a,[role=button],[data-copy],[class*=copy],[id*=copy]");
      if (!el) return;
      const attr = (name) => {
        try {
          const v = nativeGetAttribute
            ? nativeApply(nativeGetAttribute, el, [name])
            : el.getAttribute(name);
          return toPrimitiveString(v) || "";
        } catch { return ""; }
      };
      const label = `${attr("aria-label")} ${attr("title")} ` +
        `${toPrimitiveString(el.className) || ""} ${toPrimitiveString(el.id) || ""} ` +
        `${clipped(toPrimitiveString(el.textContent) || "", 80)}`;
      lastClickLooksLikeCopy = countMatches(label, [COPY_HINT]) > 0;
    } catch { /* classification is best-effort */ }
  }, true);

  // The browser's own view of user activation, which page script cannot forge.
  // Available from Chrome 115 and this extension requires 121, but it is still
  // read defensively: a missing API must not silently assert activation.
  const browserSaysActivated = () => {
    try {
      const ua = navigator.userActivation;
      return ua ? ua.isActive === true : null;
    } catch { return null; }
  };

  const context = () => {
    // nativeDateNow, not Date.now: replacing Date.now to return a constant makes
    // every write look like it followed a click, and a forged gesture turns the
    // command-shaped verdict from "block" into "warn", which forwards.
    const recentTrustedClick = nativeDateNow() - lastClickAt < 1500;
    return {
      // `isTrusted` on the listener is what makes this sound: page script cannot
      // mint a trusted event, so the gesture cannot be forged. navigator
      // .userActivation is NOT used as a veto on top of that -- transient
      // activation is consumed by other gated APIs, so a page that called one
      // between the click and the copy would report isActive=false after a
      // genuine click, and vetoing on it would block a legitimate copy button
      // for no security gain. It is reported for diagnostics instead.
      userGesture: recentTrustedClick,
      browserActivation: browserSaysActivated(),
      fromCopyControl: recentTrustedClick && lastClickLooksLikeCopy,
      host: lowered(toPrimitiveString(location.hostname) || "")
    };
  };
  // Worth being clear about the limit of the gesture rule: in the usual ClickFix
  // flow the user DOES click the fake "Verify" button, so a trusted click is
  // present and this rule will not fire. That is by design -- `lure` and
  // `stealth` are the signals that catch the common attack, and the gesture rule
  // is the backstop for the fully automated variant that writes the clipboard
  // with nothing clicked at all.

  // --- POLICY --------------------------------------------------------------
  // decide(payload, ctx) -> "allow" | "warn" | "block"
  //
  //   "allow" - write proceeds untouched.
  //   "warn"  - write proceeds, plus a dismissable banner saying the clipboard now
  //             holds a command and that pasting it into Run or Terminal executes
  //             it. Keeps legitimate copy buttons working.
  //   "block" - clipboard left untouched, attempt logged.
  //
  // Why the policy is shaped this way:
  //
  // Token counts alone cannot separate an installer from a payload, and it is
  // important to be clear about that rather than pretend a threshold exists.
  // `irm get.scoop.sh | iex` is a real installer and scores downloadExec=3; the
  // guard must not block it. So the policy leans on the two signals an honest
  // install snippet never produces, and on where the write came from:
  //
  //   lure    - a CAPTCHA/verification wrapper around a command. There is no
  //             legitimate reason to append `# ✅ I am not a robot -
  //             Verification ID: ...` to a shell command. Decisive on its own.
  //   stealth - `-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass` exists to
  //             stop the user seeing what runs. An installer wants to be seen.
  //             Decisive when the text is command-shaped.
  //   gesture - a copy button runs inside its own click handler, so a genuine copy
  //             always has a click within the last 1.5s. A page writing a command
  //             with no click behind it has no legitimate pattern.
  //
  // `ctx.fromCopyControl` deliberately does NOT downgrade a verdict: an attacker
  // can label a fake CAPTCHA button "Copy", so treating it as proof of innocence
  // would hand them the bypass. It is recorded for the log, not weighed here.
  //
  // The two error costs are not symmetric, which is what justifies blocking at
  // all. A wrong block leaves the clipboard unchanged and shows the user why -
  // they can still select the text and copy it by hand, so nothing is lost
  // permanently. A wrong allow ends in code execution on their machine. Where the
  // evidence is genuinely ambiguous the answer is "warn", so the ambiguous
  // developer cases keep working and only the clear attacks are stopped.
  function decide(payload, ctx) {
    const commandShaped = payload.execution > 0 || payload.downloadExec > 0;
    // A lure or stealth match with no command behind it is not an attack and must
    // not raise the banner: LURE_TOKENS matches "Verification ID:" and "Ray ID:",
    // which Cloudflare error pages legitimately offer to copy for support tickets.
    // The wrapper only carries meaning when it is wrapped around something.
    if (!commandShaped) return "allow";
    if (payload.lure > 0) return "block";       // CAPTCHA wrapper: no honest use
    if (payload.stealth > 0) return "block";    // hidden execution: no honest use
    if (!ctx.userGesture) return "block";       // page-initiated, nothing clicked
    return "warn";                              // ambiguous: let it through, say so
  }

  // Exposed so test/hardening.test.mjs exercises the SHIPPED tables and policy
  // rather than a copy of them, and so the classification can be inspected from
  // the console when tuning a site. Read-only surface; no page input reaches the
  // extension through it.
  try {
    nativeDefineProperty(window, "__abClickfixGuardInternals", {
      configurable: true, enumerable: false, value: nativeFreeze({ describe, decide })
    });
  } catch { /* non-essential */ }

  // --- enforcement ---------------------------------------------------------
  const report = (verdict, payload) => {
    try {
      console.warn(
        `[Advanced Privacy Blocker] ClickFix guard: ${verdict} clipboard write ` +
        `(exec=${payload.execution} dl=${payload.downloadExec} ` +
        `stealth=${payload.stealth} lure=${payload.lure})`,
        clipped(payload.text, 200)
      );
      if (!NativeCustomEvent) return;
      window.dispatchEvent(new NativeCustomEvent("advanced-blocker-clipboard-guard", {
        detail: {
          verdict,
          host: location.hostname,
          length: payload.length,
          signals: {
            execution: payload.execution, downloadExec: payload.downloadExec,
            stealth: payload.stealth, lure: payload.lure
          },
          // Truncated: enough to identify the campaign, not a full payload store.
          sample: clipped(payload.text, 300)
        }
      }));
    } catch { /* reporting must never break the page */ }
  };

  // The two verdicts need different wording: after a block the clipboard was NOT
  // changed, and telling the user it was would be both false and more alarming
  // than the situation warrants.
  const MESSAGES = {
    warn:
      "This page copied a system command to your clipboard. Pasting it into Windows " +
      "Run, PowerShell or Terminal would execute it on your computer. Legitimate " +
      "CAPTCHA and verification checks never ask you to do that.",
    block:
      "This page tried to put a system command on your clipboard and was stopped, so " +
      "your clipboard is unchanged. Pages that ask you to paste a command into Windows " +
      "Run or Terminal to “verify” yourself are attempting to run malware. If you " +
      "genuinely need this text, select it on the page and copy it yourself."
  };

  let bannerShown = false;
  function showWarning(verdict) {
    if (bannerShown) return;
    bannerShown = true;
    try {
      const bar = document.createElement("div");
      bar.setAttribute("role", "alert");
      bar.style.cssText = nativeApply(nativeArrayJoin, [
        "position:fixed", "inset:0 0 auto 0", "z-index:2147483647",
        "background:#7f1d1d", "color:#fff", "padding:14px 16px",
        "font:600 14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif",
        "box-shadow:0 2px 12px rgba(0,0,0,.45)", "display:flex",
        "gap:12px", "align-items:flex-start"
      ], [";"]);

      const msg = document.createElement("div");
      msg.style.cssText = "flex:1";
      msg.textContent = MESSAGES[verdict] || MESSAGES.warn;

      const close = document.createElement("button");
      close.type = "button";
      close.textContent = "Dismiss";
      close.style.cssText =
        "background:#fff;color:#7f1d1d;border:0;border-radius:6px;" +
        "padding:6px 12px;font:600 13px system-ui;cursor:pointer;flex:none";
      close.addEventListener("click", () => bar.remove());

      bar.append(msg, close);
      const mount = () => document.body?.appendChild(bar);
      if (document.body) mount();
      else document.addEventListener("DOMContentLoaded", mount, { once: true });
    } catch { /* a failed banner must not block the page */ }
  }

  // Returns true when the write should be suppressed.
  function intercept(text) {
    const payload = describe(text);
    if (payload.execution === 0 && payload.downloadExec === 0 &&
        payload.stealth === 0 && payload.lure === 0) {
      return false; // ordinary text: no classification, no cost
    }
    let verdict = "allow";
    try { verdict = decide(payload, context()); }
    catch { verdict = "warn"; } // a throwing policy must fail safe, not fail open
    if (verdict === "allow") return false;
    // Reporting and the banner are side effects, not part of the verdict. Both
    // touch page-replaceable machinery (CustomEvent, Array.prototype.join, the
    // textContent setter, createElement), so either can be made to throw. An
    // exception escaping here reached callers whose catch fell through to the
    // native, which turned a block into a pass -- so the decision is finished
    // before the side effects run, and they cannot undo it.
    try { report(verdict, payload); } catch { /* verdict already decided */ }
    try { showWarning(verdict); } catch { /* verdict already decided */ }
    return verdict === "block";
  }

  // Replace a method on its PROTOTYPE and lock the replacement down.
  //
  // Defining the wrapper on the `navigator.clipboard` instance instead would
  // create an own property that merely shadows the prototype, and leaving it
  // configurable/writable would let a page remove it in one line:
  //
  //     delete navigator.clipboard.writeText;   // prototype method reappears
  //     navigator.clipboard.writeText = orig;   // or just overwrite it
  //
  // Either restores the unguarded function. Patching the prototype as
  // non-configurable and non-writable closes both, and the original is reachable
  // only through the closure below. These two methods are effectively never
  // monkey-patched by legitimate code, so locking them carries little breakage
  // risk -- unlike `window.open`, which libraries do wrap (see popup-guard.js).
  // Natives captured at document_start, before any page script runs, so later
  // tampering with these prototypes cannot change how the guard reads data.
  // Give a snapshot its OWN non-writable @@iterator that walks indices.
  //
  // Handing a plain Array to the native is not enough. WebIDL's
  // sequence<ClipboardItem> conversion does GetMethod(value, @@iterator), which
  // on an ordinary array resolves through Array.prototype[Symbol.iterator] - and
  // the page can replace that with a stateful function, so the classifier's pass
  // and the native's pass see different values (verified: the guard classifies
  // the first yield while the native iterates the second). An own,
  // non-configurable, non-writable iterator is found before the prototype, so the
  // native can only ever walk the entries we inspected. Hand-rolled rather than a
  // generator, to avoid depending on %GeneratorPrototype% being untampered.
  // Returns the sealed array, or null if the seal could not be VERIFIED. A
  // replaced Object.defineProperty that silently does nothing would not throw, so
  // trusting the try/catch alone would fail open: the caller forwards an array
  // whose iterator still resolves through the (page-controlled) prototype. The
  // descriptor is therefore read back through a captured accessor and checked.
  const sealSequence = (arr) => {
    try {
      nativeDefineProperty(arr, Symbol.iterator, {
        configurable: false, enumerable: false, writable: false,
        value: function () {
          let i = 0;
          return {
            next: () => {
              if (i >= arr.length) return { value: undefined, done: true };
              const value = arr[i];
              i += 1;
              return { value, done: false };
            }
          };
        }
      });
    } catch { return null; }
    try {
      const d = nativeGetOwnPropertyDescriptor(arr, Symbol.iterator);
      if (!d || typeof d.value !== "function" || d.writable || d.configurable) return null;
    } catch { return null; }
    return arr;
  };
  const nativeBlobText = typeof Blob === "function" ? Blob.prototype.text : null;
  const nativeItemGetType = typeof ClipboardItem === "function"
    ? ClipboardItem.prototype.getType : null;
  const nativeItemTypes = (() => {
    try {
      if (typeof ClipboardItem !== "function") return null;
      return nativeGetOwnPropertyDescriptor(ClipboardItem.prototype, "types")?.get || null;
    } catch { return null; }
  })();

  const lockMethod = (holder, name, build) => {
    try {
      const native = holder?.[name];
      if (typeof native !== "function") return false;
      nativeDefineProperty(holder, name, {
        configurable: false, enumerable: false, writable: false,
        value: build(native)
      });
      return true;
    } catch { return false; }
  };

  // 1 & 2. Clipboard.prototype.writeText / .write
  try {
    const clipboardProto = navigator.clipboard
      ? nativeGetPrototypeOf(navigator.clipboard)
      : (typeof Clipboard === "function" ? Clipboard.prototype : null);

    if (clipboardProto) {
      lockMethod(clipboardProto, "writeText", (native) => function writeText(text) {
        // Coerce EXACTLY ONCE, classify that primitive, and hand the SAME
        // primitive to the native call. Classifying `text` and then forwarding
        // `text` would be a time-of-check/time-of-use gap: an argument whose
        // toString() returns a different value on each call gets coerced twice,
        // once by us and once by the WebIDL binding, so
        //
        //   let n = 0;
        //   writeText({ toString: () => n++ ? "powershell -c ..." : "hello" })
        //
        // would be classified as "hello" and written as the payload.
        // `this` keeps the call bound to whichever Clipboard instance was used.
        const value = toPrimitiveString(text);
        if (value === null || intercept(value)) return nativePromiseResolve();
        return nativeApply(native, this, [value]);
      });

      lockMethod(clipboardProto, "write", (native) => function write(items) {
        // Read each item through the natives captured at startup, never through
        // its own properties. Platform objects are extensible, so a page can
        // shadow the `types` getter or `getType` with an own property that
        // reports no text while the native call still writes the real payload
        // from the object's internal slots:
        //
        //   Object.defineProperty(item, "types", { value: [] });
        //
        // Captured accessors read the internal slots, so shadowing is inert.
        //
        // Snapshot the sequence ONCE and forward the snapshot. `items` is an
        // attacker-controlled iterable, so iterating it here to classify and then
        // handing the original to the native - which iterates it again - is the
        // same time-of-check/time-of-use gap as the string coercion above, just
        // with a different primitive: a custom Symbol.iterator can yield benign
        // items on the first pass and payload items on the second. The snapshot is
        // taken with a captured Array.from and walked by index, so neither a
        // replaced Array.prototype[Symbol.iterator] nor a re-iterating source can
        // make the native see anything the classifier did not.
        const list = sealSequence(nativeArrayFrom(items || []));
        // Fail CLOSED. Sealing only fails when the environment has been tampered
        // with, which is itself hostile, so there is no legitimate copy to
        // protect here -- unlike an unreadable item, which can be a real image.
        if (list === null || !nativeIsArray(list)) {
          report("block", describe("[clipboard sequence could not be secured]"));
          showWarning("block");
          return nativePromiseResolve();
        }

        // Deliberately NOT an async function: `await` on the promises returned by
        // getType()/text() is page-interceptable (see the capture block). The walk
        // is driven by captured `then` callbacks instead.
        const self = this;
        return new NativePromise((resolve, reject) => {
          let anomalous = false;

          const forward = () => {
            // An item we could not read is not proof of innocence. Say so rather
            // than passing it through silently -- but warn instead of blocking,
            // because a legitimate non-text item (an image from a "copy image"
            // button) must still reach the clipboard.
            if (anomalous) report("warn", describe("[unreadable clipboard item]"));
            try {
              nativeApply(nativeThen, nativeApply(native, self, [list]), [resolve, reject]);
            } catch (error) { reject(error); }
          };

          // Separate "could not read this item" from "the environment lied to
          // us". Promise.prototype.then performs SpeciesConstructor(p, %Promise%),
          // which reads the page-replaceable Promise.prototype.constructor, so a
          // hostile constructor can make an intrinsic promise's `then` throw
          // synchronously. Routing that through the unreadable-item path would
          // warn and forward -- turning a block into a pass, which is the whole
          // bypass. A captured native throwing on an intrinsic promise is never
          // honest, so fail closed instead.
          const tamper = () => {
            report("block", describe("[clipboard promise chain could not be secured]"));
            showWarning("block");
            resolve(undefined);
          };

          const step = (i) => {
            if (i >= list.length) return forward();
            const item = list[i];
            const skip = () => step(i + 1);
            const fail = () => { anomalous = true; skip(); };

            let types;
            try {
              types = nativeItemTypes ? nativeApply(nativeItemTypes, item, []) : item?.types;
            } catch { return fail(); }

            let hasText = false;
            try {
              // Not Boolean(types): Boolean is a page-replaceable global, and
              // Boolean = () => false made hasText false for every item, so the
              // sequence was forwarded unclassified. Verified as a bypass.
              hasText = types != null &&
                nativeApply(nativeIncludes, types, ["text/plain"]) === true;
            } catch { return fail(); }
            if (!hasText) return skip();

            let blobPromise;
            try {
              blobPromise = nativeItemGetType
                ? nativeApply(nativeItemGetType, item, ["text/plain"])
                : item.getType("text/plain");
            } catch { return fail(); }

            try {
              nativeApply(nativeThen, blobPromise, [(blob) => {
                let textPromise;
                try {
                  textPromise = nativeBlobText
                    ? nativeApply(nativeBlobText, blob, [])
                    : blob.text();
                } catch { return fail(); }
                try {
                  nativeApply(nativeThen, textPromise, [(text) => {
                    const asString = toPrimitiveString(text);
                    if (asString === null) return fail();
                    // Blocked: never reach the native, and resolve so callers
                    // chaining .then() are not left pending.
                    if (intercept(asString)) return resolve(undefined);
                    return skip();
                  }, fail]);
                } catch { return tamper(); }
              }, fail]);
            } catch { return tamper(); }
          };

          step(0);
        });
      });
    }
  } catch { /* clipboard unavailable (insecure context): nothing to guard */ }

  // 3. A `copy` listener that rewrites what the user copies. Classic ClickFix:
  //    the user selects "verification text" and the page swaps in a command.
  //
  //    Intercepting at `setData` time rather than in a copy listener is what makes
  //    this reliable. A listener cannot win on ordering: ours runs in the capture
  //    phase, so a page handler attached to the target calls
  //    `event.clipboardData.setData(...)` AFTER we have already read the event --
  //    we would inspect empty data and wave the injection through. Wrapping
  //    DataTransfer.prototype.setData sees the write whenever it happens, in any
  //    handler, in any phase.
  try {
    if (typeof DataTransfer === "function") {
      lockMethod(DataTransfer.prototype, "setData", (native) => function setData(format, data) {
        // Coerce both arguments once, for the same time-of-check/time-of-use
        // reason as writeText above, and pass the primitives on.
        const fmt = toPrimitiveString(format);
        const value = toPrimitiveString(data);
        if (fmt === null || value === null) return undefined; // refuse unreducible input
        // No format allowlist. Matching only `text/plain`/`text` meant reasoning
        // about how the browser normalises a format string ("TEXT/Plain", a
        // trailing parameter, surrounding whitespace, the text -> text/plain and
        // url -> text/uri-list aliases) and any mismatch between that reasoning
        // and the engine would be a bypass. Classifying every string written
        // through setData removes the differential entirely, and costs nothing:
        // intercept() returns immediately for text with no command tokens, which
        // is every ordinary copy.
        // Fail CLOSED, for the same reason as execCommand's copy branch: the old
        // `catch { fall through to native }` meant anything that threw while
        // classifying forwarded the payload unchecked. intercept() is not
        // supposed to throw -- its side effects are guarded -- so a throw here is
        // an anomaly, and dropping the write costs at most one lost copy.
        let blocked;
        try { blocked = intercept(value); }
        catch { return undefined; }
        if (blocked) return undefined; // drop: clipboard keeps its old contents
        return nativeApply(native, this, [fmt, value]);
      });
    }
  } catch { /* DataTransfer unavailable: the copy listener below still applies */ }

  //    The listener is kept as a second line of defence, for a page that replaces
  //    the whole selection rather than calling setData.
  document.addEventListener("copy", (event) => {
    try {
      const dt = nativeEventClipboardData
        ? nativeApply(nativeEventClipboardData, event, [])
        : event.clipboardData;
      const injected = toPrimitiveString(
        dt && nativeDTGetData ? nativeApply(nativeDTGetData, dt, ["text/plain"]) : dt?.getData?.("text/plain")
      ) || "";
      if (!injected) return;
      const selected = readSelection();
      // Only inspect writes that do NOT match the selection: an unmodified copy
      // of what the user highlighted is their own action, whatever it says.
      // Captured trim, so String.prototype.trim cannot be replaced to make any
      // injected text compare equal to the selection and skip the check.
      if (selected && trimmed(injected) === trimmed(selected)) return;
      if (intercept(injected)) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    } catch { /* never interfere with a normal copy */ }
  }, true);

  // What execCommand("copy") will actually copy. Read through captured getters:
  // `active.value` finds a page-defined own property if there is one, so
  //
  //   Object.defineProperty(input, "value", { get: () => "harmless text" })
  //
  // had the classifier inspect text that is never written while the browser
  // copied the real selection from internal slots. Verified as a bypass.
  //
  // A focused field's copy takes its SELECTION, and this classifies the whole
  // value. That is deliberate: the value is a superset of the selection, so a
  // partial selection can only ever be judged more strictly, never less.
  const readCopySource = (doc) => {
    const active = nativeActiveElement
      ? nativeApply(nativeActiveElement, doc, [])
      : doc.activeElement;
    if (active != null) {
      const getters = [nativeInputValue, nativeTextAreaValue];
      for (let i = 0; i < getters.length; i += 1) {
        if (!getters[i]) continue;
        let value;
        try { value = nativeApply(getters[i], active, []); }
        catch { continue; } // not this element type
        return toPrimitiveString(value);
      }
      // No captured value getter for this element type. Fall back to the own
      // property, which is what a non-browser host (or a very old engine) gives
      // us. This path is page-shadowable by construction; the captured getters
      // above are the ones that matter in Chromium.
      if ("value" in active) return toPrimitiveString(active.value);
    }
    return readSelection();
  };

  // 4. document.execCommand("copy") against a page-controlled selection.
  //    Patched on Document.prototype for the same reason as the clipboard methods.
  try {
    const documentProto = typeof Document === "function"
      ? Document.prototype
      : nativeGetPrototypeOf(document);
    lockMethod(documentProto, "execCommand", (native) => function execCommand(command, ...rest) {
      // Coerce ONCE and forward the coerced value. Classifying
      // toPrimitiveString(command) and then forwarding the original `command` was
      // the same mistake already fixed in writeText and setData: a mutating
      // toString lets the guard read "notcopy" and skip classification while the
      // native reads "copy" and performs the copy unchecked.
      const cmd = toPrimitiveString(command);
      if (cmd === null) return false;
      // Captured toLowerCase. String.prototype.toLowerCase = () => "notcopy" made
      // the guard skip classification while the native still performed the copy.
      let isCopy;
      try { isCopy = lowered(cmd) === "copy"; }
      catch { isCopy = true; } // cannot tell: classify rather than wave through
      if (isCopy) {
        // Fail CLOSED from here. The previous `catch { fall through to native }`
        // meant anything that threw while classifying -- a hostile activeElement
        // getter, a replaced CustomEvent making report() throw -- forwarded the
        // copy unchecked. For a copy command a throw is anomalous, not ordinary.
        let source;
        try { source = readCopySource(this); }
        catch { return false; }
        if (source === null) return false;
        let blocked;
        try { blocked = intercept(source); }
        catch { return false; }
        if (blocked) return false;
      }
      // Build the argument list by index: a spread would use the array iterator,
      // which is page-replaceable.
      const args = [cmd];
      for (let i = 0; i < rest.length; i += 1) args[i + 1] = rest[i];
      return nativeApply(native, this, args);
    });
  } catch { /* leave execCommand alone if it cannot be wrapped */ }
})();
