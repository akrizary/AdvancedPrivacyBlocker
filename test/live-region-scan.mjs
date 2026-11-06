// Scan clickfix-guard.js for call-time lookups of page-replaceable things.
//
// Why this exists. Seven security-review rounds on that file found the same
// mistake seven times: the guard classified one value and handed the native a
// different one, or it let the page own the tools it classified with. Rounds
// five and six answered with a DENYLIST test -- six intrinsic names the source
// must not mention after the capture block. That test passed while
//
//   countMatches = (text, patterns) => patterns.reduce((n, re) => n + (re.test(text) ? 1 : 0), 0)
//
// sat in the classifier core, where either Array.prototype.reduce = () => 0 or
// RegExp.prototype.test = () => false zeroes every token count and makes
// decide() return "allow" on all four hook paths. A denylist can only catch the
// names someone already thought of, which is exactly the wrong shape for a
// recurring blind spot.
//
// So this is an ALLOWLIST. Every bare call in the live region must resolve to a
// local or to a captured native, and every method call must be on the reviewed
// list below. Adding an un-captured lookup fails the suite instead of waiting
// for the next review.

// Strip comments and literals with a single-pass scanner that tracks lexical
// state. Layered regexes were tried first and were not good enough: stripping
// line comments before regex literals made trailing-comment words read as code
// ("// DNS-staged variant (2026)" became a call to `variant`), and stripping
// them after let a "/" inside comment prose open a phantom regex literal that
// swallowed the next three function declarations whole. A scanner that knows
// which state it is in has neither failure, and a test that silently loses part
// of the file it is meant to be checking is worse than no test.
function stripToCode(src) {
  const out = [];
  let i = 0;
  // The last meaningful code character, which decides whether "/" opens a regex
  // literal or is a division operator.
  let prev = "";
  const REGEX_OK_AFTER = new Set(["", "=", "(", ",", "[", ":", "!", "&", "|", "?",
    "{", "}", ";", "+", "-", "*", "%", "~", "^", "<", ">", "\n"]);
  const KEYWORD_BEFORE_REGEX = /\b(?:return|typeof|case|in|of|new|delete|void|instanceof)$/;

  while (i < src.length) {
    const c = src[i];
    const two = src.substr(i, 2);

    if (two === "//") {
      while (i < src.length && src[i] !== "\n") i += 1;
      out.push(" ");
      continue;
    }
    if (two === "/*") {
      i += 2;
      while (i < src.length && src.substr(i, 2) !== "*/") i += 1;
      i += 2;
      out.push(" ");
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = c;
      i += 1;
      while (i < src.length && src[i] !== quote) i += src[i] === "\\" ? 2 : 1;
      i += 1;
      out.push('"S"');
      prev = '"';
      continue;
    }
    if (c === "`") {
      // Template literals may contain ${ ... } with real code in it. Keep the
      // interpolations and drop the text, so `${attr("title")}` still counts as
      // a call to attr.
      i += 1;
      out.push('"S"');
      while (i < src.length && src[i] !== "`") {
        if (src[i] === "\\") { i += 2; continue; }
        if (src.substr(i, 2) === "${") {
          let depth = 1;
          i += 2;
          const start = i;
          while (i < src.length && depth > 0) {
            if (src[i] === "{") depth += 1;
            else if (src[i] === "}") depth -= 1;
            if (depth > 0) i += 1;
          }
          out.push(" ", stripToCode(src.slice(start, i)), " ");
          i += 1;
          continue;
        }
        i += 1;
      }
      i += 1;
      prev = '"';
      continue;
    }
    if (c === "/") {
      const tail = out.join("");
      const opensRegex = REGEX_OK_AFTER.has(prev) || KEYWORD_BEFORE_REGEX.test(tail.trimEnd());
      if (opensRegex) {
        i += 1;
        let inClass = false;
        while (i < src.length) {
          const d = src[i];
          if (d === "\\") { i += 2; continue; }
          if (d === "[") inClass = true;
          else if (d === "]") inClass = false;
          else if (d === "/" && !inClass) break;
          else if (d === "\n") break; // unterminated: not a regex after all
          i += 1;
        }
        i += 1;
        while (i < src.length && /[gimsuyd]/.test(src[i])) i += 1;
        out.push("RE");
        prev = "E";
        continue;
      }
    }
    out.push(c);
    if (!/\s/.test(c)) prev = c;
    else if (c === "\n") prev = "\n";
    i += 1;
  }
  return out.join("");
}

/**
 * The part of the source that runs with page-replaceable globals in scope:
 * everything after the capture block, reduced to code.
 */
export function liveRegion(src) {
  const parts = src.split("const toPrimitiveString");
  if (parts.length < 2) throw new Error("capture-block marker not found");
  return stripToCode(parts.slice(1).join("const toPrimitiveString"));
}

/** Names declared in the live region, so they are not mistaken for globals. */
export function localNames(live) {
  const locals = new Set();
  for (const m of live.matchAll(/\b(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)/g)) {
    locals.add(m[1]);
  }
  const params = (text) => {
    for (const part of text.split(",")) {
      const n = part.trim().replace(/^\.\.\./, "").split(/[=:]/)[0].trim();
      if (/^[A-Za-z_$][\w$]*$/.test(n)) locals.add(n);
    }
  };
  for (const m of live.matchAll(/\(([^()]*)\)\s*=>/g)) params(m[1]);
  for (const m of live.matchAll(/function\s*[\w$]*\s*\(([^()]*)\)/g)) params(m[1]);
  for (const m of live.matchAll(/([A-Za-z_$][\w$]*)\s*=>/g)) locals.add(m[1]);
  return locals;
}

const KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "return", "typeof",
  "function", "new", "else", "do", "try", "await", "void", "delete", "in", "of", "RE"]);

/** Bare identifiers called or constructed that are not locals. */
export function bareCalls(live, locals) {
  const out = new Set();
  for (const m of live.matchAll(/(?:^|[^.\w$])(?:new\s+)?([A-Za-z_$][\w$]*)\s*\(/g)) {
    if (KEYWORDS.has(m[1]) || locals.has(m[1])) continue;
    out.add(m[1]);
  }
  return [...out].sort();
}

/** Method calls written as `.name(`. */
export function methodCalls(live) {
  const out = new Set();
  for (const m of live.matchAll(/\.([A-Za-z_$][\w$]*)\s*\(/g)) out.add(m[1]);
  return [...out].sort();
}

// Bare calls allowed in the live region: captured natives, plus the one helper
// that wraps the captured String. Anything else is a call-time global lookup.
export const ALLOWED_BARE = /^(?:native[A-Z]|Native[A-Z])|^toPrimitiveString$/;

// Method calls allowed in the live region. Two groups, and nothing else:
//
//  - DOM side effects that cannot lie to the classifier. Replacing them can
//    break the banner or stop the copy event being cancelled, but it cannot make
//    the guard read text the native will not write. The guard registers its
//    listeners at document_start, before page script runs, and each of these now
//    sits inside a try/catch whose failure cannot forward a payload.
//  - Documented fallbacks for when a capture is unavailable, each written as
//    `captured ? nativeApply(captured, ...) : obj.method(...)`, so the fallback
//    is only reached on a host that never had the native to capture.
export const ALLOWED_METHODS = new Set([
  // side effects
  "addEventListener", "append", "appendChild", "createElement", "dispatchEvent",
  "preventDefault", "remove", "setAttribute", "stopImmediatePropagation", "warn",
  // capture-unavailable fallbacks
  "getAttribute", "getSelection", "getType", "text"
]);

export function scan(src) {
  const live = liveRegion(src);
  const locals = localNames(live);
  return {
    live,
    locals,
    bare: bareCalls(live, locals).filter((n) => !ALLOWED_BARE.test(n)),
    methods: methodCalls(live).filter((n) => !ALLOWED_METHODS.has(n))
  };
}
