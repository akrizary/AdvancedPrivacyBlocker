// Shared registrable-domain (approximate eTLD+1) helper.
//
// This is an approximation of the Public Suffix List: it handles common
// multi-part suffixes explicitly and otherwise falls back to the last two
// labels. It is used for third-party detection and display labels only, so
// imprecision on unusual ccTLDs is harmless.
//
// NOTE: lib/content-tools.js keeps its own inline copy of registrableApprox
// because it runs as a classic content script and cannot `import` ES modules.
// If you change the logic or MULTI_PART_SUFFIXES here, mirror it there.
export const MULTI_PART_SUFFIXES = Object.freeze(new Set([
  "co.uk", "org.uk", "com.au", "com.br", "co.jp", "com.my", "com.sg", "co.nz", "co.in"
]));

export function registrableApprox(host) {
  const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const tail2 = parts.slice(-2).join(".");
  return MULTI_PART_SUFFIXES.has(tail2) ? parts.slice(-3).join(".") : tail2;
}
