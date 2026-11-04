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
//
// background.js registers this only while the `clickfixGuard` setting is on.
(() => {
  "use strict";
  if (window.__abClickfixGuard) return;
  window.__abClickfixGuard = true;

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

  const countMatches = (text, patterns) => patterns.reduce((n, re) => n + (re.test(text) ? 1 : 0), 0);

  // A structured description of the payload, so policy reads as policy.
  function describe(text) {
    const value = String(text == null ? "" : text);
    return {
      text: value,
      length: value.length,
      lines: value.split("\n").length,
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
    lastClickAt = Date.now();
    lastClickLooksLikeCopy = false;
    try {
      const el = event.target?.closest?.("button,a,[role=button],[data-copy],[class*=copy],[id*=copy]");
      if (!el) return;
      const label = `${el.getAttribute("aria-label") || ""} ${el.getAttribute("title") || ""} ` +
        `${el.className || ""} ${el.id || ""} ${(el.textContent || "").slice(0, 80)}`;
      lastClickLooksLikeCopy = COPY_HINT.test(label);
    } catch { /* classification is best-effort */ }
  }, true);

  // The browser's own view of user activation, which page script cannot forge.
  // Available from Chrome 115 and this extension requires 121, but it is still
  // read defensively: a missing API must not silently assert activation.
  const browserSaysActivated = () => {
    try {
      const ua = navigator.userActivation;
      return ua ? Boolean(ua.isActive) : null;
    } catch { return null; }
  };

  const context = () => {
    const recentTrustedClick = Date.now() - lastClickAt < 1500;
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
      host: location.hostname.toLowerCase()
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
    Object.defineProperty(window, "__abClickfixGuardInternals", {
      configurable: true, enumerable: false, value: Object.freeze({ describe, decide })
    });
  } catch { /* non-essential */ }

  // --- enforcement ---------------------------------------------------------
  const report = (verdict, payload) => {
    try {
      console.warn(
        `[Advanced Privacy Blocker] ClickFix guard: ${verdict} clipboard write ` +
        `(exec=${payload.execution} dl=${payload.downloadExec} ` +
        `stealth=${payload.stealth} lure=${payload.lure})`,
        payload.text.slice(0, 200)
      );
      window.dispatchEvent(new CustomEvent("advanced-blocker-clipboard-guard", {
        detail: {
          verdict,
          host: location.hostname,
          length: payload.length,
          signals: {
            execution: payload.execution, downloadExec: payload.downloadExec,
            stealth: payload.stealth, lure: payload.lure
          },
          // Truncated: enough to identify the campaign, not a full payload store.
          sample: payload.text.slice(0, 300)
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
      bar.style.cssText = [
        "position:fixed", "inset:0 0 auto 0", "z-index:2147483647",
        "background:#7f1d1d", "color:#fff", "padding:14px 16px",
        "font:600 14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif",
        "box-shadow:0 2px 12px rgba(0,0,0,.45)", "display:flex",
        "gap:12px", "align-items:flex-start"
      ].join(";");

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
    report(verdict, payload);
    showWarning(verdict);
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
  const lockMethod = (holder, name, build) => {
    try {
      const native = holder?.[name];
      if (typeof native !== "function") return false;
      Object.defineProperty(holder, name, {
        configurable: false, enumerable: false, writable: false,
        value: build(native)
      });
      return true;
    } catch { return false; }
  };

  // 1 & 2. Clipboard.prototype.writeText / .write
  try {
    const clipboardProto = navigator.clipboard
      ? Object.getPrototypeOf(navigator.clipboard)
      : (typeof Clipboard === "function" ? Clipboard.prototype : null);

    if (clipboardProto) {
      lockMethod(clipboardProto, "writeText", (native) => function writeText(text) {
        // `this` keeps the call bound to whichever Clipboard instance was used.
        if (intercept(text)) return Promise.resolve(); // resolve: callers chain .then()
        return native.call(this, text);
      });

      lockMethod(clipboardProto, "write", (native) => async function write(items) {
        try {
          for (const item of items || []) {
            if (!item?.types?.includes?.("text/plain")) continue;
            const blob = await item.getType("text/plain");
            if (intercept(await blob.text())) return;
          }
        } catch { /* unreadable item: fall through to native */ }
        return native.call(this, items);
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
        try {
          if (/^(text\/plain|text|text\/x-moz-url)$/i.test(String(format)) &&
              intercept(data)) {
            return undefined; // silently drop: the clipboard keeps its old contents
          }
        } catch { /* fall through to native */ }
        return native.call(this, format, data);
      });
    }
  } catch { /* DataTransfer unavailable: the copy listener below still applies */ }

  //    The listener is kept as a second line of defence, for a page that replaces
  //    the whole selection rather than calling setData.
  document.addEventListener("copy", (event) => {
    try {
      const injected = event.clipboardData?.getData?.("text/plain");
      if (!injected) return;
      const selected = String(window.getSelection?.() || "");
      // Only inspect writes that do NOT match the selection: an unmodified copy
      // of what the user highlighted is their own action, whatever it says.
      if (selected && injected.trim() === selected.trim()) return;
      if (intercept(injected)) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    } catch { /* never interfere with a normal copy */ }
  }, true);

  // 4. document.execCommand("copy") against a page-controlled selection.
  //    Patched on Document.prototype for the same reason as the clipboard methods.
  try {
    const documentProto = typeof Document === "function"
      ? Document.prototype
      : Object.getPrototypeOf(document);
    lockMethod(documentProto, "execCommand", (native) => function execCommand(command, ...rest) {
      try {
        if (String(command).toLowerCase() === "copy") {
          const active = this.activeElement;
          const value = active && "value" in active
            ? active.value
            : String(window.getSelection?.() || "");
          if (intercept(value)) return false;
        }
      } catch { /* fall through to native */ }
      return native.call(this, command, ...rest);
    });
  } catch { /* leave execCommand alone if it cannot be wrapped */ }
})();
