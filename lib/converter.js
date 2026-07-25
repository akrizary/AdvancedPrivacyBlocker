const TYPE_MAP = {
  script: "script", image: "image", stylesheet: "stylesheet", object: "object",
  xmlhttprequest: "xmlhttprequest", subdocument: "sub_frame", ping: "ping",
  media: "media", font: "font", websocket: "websocket", other: "other",
  document: "main_frame"
};

const KNOWN_OPTS = new Set([
  "third-party", "domain", "script", "image", "stylesheet", "object",
  "xmlhttprequest", "subdocument", "ping", "media", "font", "websocket",
  "other", "document", "match-case", "important", "popup", "genericblock",
  "generichide", "elemhide", "csp", "redirect", "redirect-rule", "removeparam", "all"
]);
const MAX_REGEX_RULES = 1000;

function cleanDomains(list) {
  const out = [];
  for (let value of list) {
    value = String(value || "").trim().toLowerCase().replace(/^\|\|/, "").replace(/\^$/, "");
    if (!value || /[^a-z0-9.-]/.test(value) || !/[a-z0-9]/.test(value)) continue;
    out.push(value.replace(/^\.+|\.+$/g, ""));
  }
  return [...new Set(out.filter(Boolean))];
}

function splitOptions(pattern) {
  if (pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/")) return { pattern, options: "" };
  const dollar = pattern.lastIndexOf("$");
  if (dollar === -1) return { pattern, options: "" };
  const after = pattern.slice(dollar + 1);
  if (!after || after.includes("/")) return { pattern, options: "" };
  const valid = after.split(",").every(token => {
    const name = (token.startsWith("~") ? token.slice(1) : token).split("=")[0];
    return KNOWN_OPTS.has(name);
  });
  return valid ? { pattern: pattern.slice(0, dollar), options: after } : { pattern, options: "" };
}

function normalizePattern(pattern) {
  if (!pattern || (pattern.startsWith("/") && pattern.endsWith("/"))) return "";
  if (/[^\x00-\x7F]/.test(pattern)) return "";
  let value = pattern.startsWith("||*") ? pattern.slice(2) : pattern;
  if (!value) return "";
  let body = value;
  if (body.startsWith("||")) body = body.slice(2);
  else if (body.startsWith("|")) body = body.slice(1);
  if (body.endsWith("|")) body = body.slice(0, -1);
  if (body.includes("|")) return "";
  return value;
}

function parseCosmetic(line) {
  const markers = ["#@#", "##"];
  for (const marker of markers) {
    const index = line.indexOf(marker);
    if (index < 0) continue;
    const left = line.slice(0, index);
    const selector = line.slice(index + marker.length).trim();
    if (!selector || selector.startsWith("+js(") || selector.startsWith("^")) return null;
    const domains = [], excludedDomains = [];
    for (let domain of left.split(",").map(value => value.trim()).filter(Boolean)) {
      const excluded = domain.startsWith("~");
      if (excluded) domain = domain.slice(1);
      const cleaned = cleanDomains([domain])[0];
      if (!cleaned) continue;
      (excluded ? excludedDomains : domains).push(cleaned);
    }
    return { domains, excludedDomains, selector, exception: marker === "#@#" };
  }
  return null;
}

function auditException(rawLine, condition) {
  const reasons = [];
  const scoped = Boolean(condition.initiatorDomains?.length || condition.resourceTypes?.length);
  const filter = condition.urlFilter || condition.regexFilter || "";
  const stripped = filter.replace(/[|^*]/g, "");
  if (!scoped) {
    if (stripped.length <= 4) reasons.push("Very short filter with no domain/type scope");
    else if (/^\|\|[a-z0-9.-]+\^?$/i.test(filter)) reasons.push("Whole-domain allow with no type scope");
  }
  if (/\$document\b/.test(rawLine) && !condition.initiatorDomains?.length) reasons.push("$document exception without domain scope");
  if (!filter || filter === "*" || filter === "||*") reasons.push("Wildcard/empty filter matches all requests");
  return reasons;
}

export async function parseFilterList(text, startId = 100000, options = {}) {
  const network = [], cosmetic = [], flaggedExceptions = [];
  let id = startId, regexCount = 0;
  const regexValidator = options.regexValidator || (async regex => {
    try {
      if (!globalThis.chrome?.declarativeNetRequest?.isRegexSupported) return false;
      const result = await chrome.declarativeNetRequest.isRegexSupported({ regex });
      return Boolean(result?.isSupported);
    } catch { return false; }
  });

  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("!") || line.startsWith("[")) continue;

    if (!line.includes("://") && (line.includes("##") || line.includes("#@#"))) {
      const parsedCosmetic = parseCosmetic(line);
      if (parsedCosmetic) cosmetic.push(parsedCosmetic);
      continue;
    }
    if (line.includes("#?#") || line.includes("#$#") || line.includes("#%#") || line.startsWith("#")) continue;

    const isException = line.startsWith("@@");
    const body = isException ? line.slice(2) : line;
    const { pattern, options: optionText } = splitOptions(body);
    const isRegex = pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/");
    const condition = {};
    const resourceTypes = new Set(), excludedTypes = new Set();
    let initiatorDomains = null, excludedInitiatorDomains = null, dropRule = false;
    let unsupportedProcedural = false;

    for (const token of optionText.split(",").filter(Boolean)) {
      const negative = token.startsWith("~");
      const normalized = negative ? token.slice(1) : token;
      const [key, ...valueParts] = normalized.split("=");
      const value = valueParts.join("=");
      if (TYPE_MAP[key]) (negative ? excludedTypes : resourceTypes).add(TYPE_MAP[key]);
      else if (key === "third-party") condition.domainType = negative ? "firstParty" : "thirdParty";
      else if (["removeparam", "redirect", "redirect-rule", "csp"].includes(key)) unsupportedProcedural = true;
      else if (key === "domain" && value) {
        const include = [], exclude = [];
        for (let domain of value.split("|")) {
          if (!domain) continue;
          if (domain.startsWith("~")) exclude.push(domain.slice(1));
          else include.push(domain);
        }
        if (include.length) {
          initiatorDomains = cleanDomains(include);
          if (!initiatorDomains.length) dropRule = true;
        }
        if (exclude.length) excludedInitiatorDomains = cleanDomains(exclude);
      }
      // Other non-network presentation options are intentionally ignored.
    }
    if (dropRule || unsupportedProcedural) continue;

    if (isRegex) {
      if (regexCount >= MAX_REGEX_RULES) continue;
      const regex = pattern.slice(1, -1);
      if (!regex || !(await regexValidator(regex))) continue;
      condition.regexFilter = regex;
      regexCount += 1;
    } else {
      const urlFilter = normalizePattern(pattern);
      if (!urlFilter) continue;
      condition.urlFilter = urlFilter;
    }

    if (resourceTypes.size) condition.resourceTypes = [...resourceTypes];
    if (excludedTypes.size) condition.excludedResourceTypes = [...excludedTypes];
    if (initiatorDomains?.length) condition.initiatorDomains = initiatorDomains;
    if (excludedInitiatorDomains?.length) condition.excludedInitiatorDomains = excludedInitiatorDomains;

    const filterValue = condition.urlFilter || condition.regexFilter || "";
    const globallyBlanket = !isRegex && ["*", "||*", "|*|", "|*"].includes(filterValue);
    const hasScope = Boolean(condition.initiatorDomains?.length || condition.excludedInitiatorDomains?.length || condition.resourceTypes?.length || condition.excludedResourceTypes?.length || condition.domainType);
    if (!isException && globallyBlanket && !hasScope) continue;

    const rule = {
      id: id++,
      priority: isException ? 2 : 1,
      action: { type: isException ? "allow" : "block" },
      condition
    };
    network.push(rule);
    if (isException) {
      const reasons = auditException(line, condition);
      if (reasons.length) flaggedExceptions.push({ line, reasons, ruleId: rule.id });
    }
  }

  return {
    network, cosmetic, regexCount, flaggedExceptions,
    exceptionCount: network.filter(rule => rule.action.type === "allow").length,
    blockCount: network.filter(rule => rule.action.type === "block").length
  };
}

export const __test = { cleanDomains, splitOptions, normalizePattern, parseCosmetic, auditException };
