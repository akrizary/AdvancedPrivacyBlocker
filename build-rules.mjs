// build-rules.mjs
// Pre-generates FEATURE-GROUPED static rulesets from filter lists, writes the
// ruleset metadata and per-feature cosmetic files, and rewrites the manifest.
// Output contract (consumed by background.js):
//   rules/generated/{feature}_static_{index}.json  - DNR rule arrays (globally unique ids)
//   rules/generated/cosmetic-{feature}.json        - [{domains, selector}]
//   rules/generated/ruleset-metadata.json          - { rulesets: [{id,feature,source,sourceLocation,index,count,allowIds}] }
//   manifest.json declarative_net_request           - core_* seeds + backup preserved, generated appended (enabled:false)
// Usage: node build-rules.mjs   (Node 18+, built-in fetch, no dependencies)
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

// Sources mirror the ENABLED built-in subscriptions in background.js so the
// static baseline matches what the extension fetches remotely. `malware`
// includes both security feeds; baked here they get always-win static coverage.
const LISTS = [
  { feature: "ads",        source: "EasyList",              url: "https://easylist.to/easylist/easylist.txt" },
  { feature: "ads",        source: "ABPindo (ID/MY)",       url: "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt" },
  { feature: "ads",        source: "AdGuard Mobile Ads",    url: "https://filters.adtidy.org/extension/chromium/filters/11.txt" },
  { feature: "tracking",   source: "EasyPrivacy",           url: "https://easylist.to/easylist/easyprivacy.txt" },
  { feature: "tracking",   source: "AdGuard Tracking",      url: "https://filters.adtidy.org/extension/chromium/filters/3.txt" },
  { feature: "annoyances", source: "AdGuard Annoyances",    url: "https://filters.adtidy.org/extension/chromium/filters/14.txt" },
  { feature: "malware",    source: "URLHaus Online",        url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt" },
  { feature: "malware",    source: "Phishing/Malvertising", url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt" },
  { feature: "malware",    source: "Botnet C2",             url: "https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt" },
  { feature: "malware",    source: "PUP/Adware",            url: "https://malware-filter.gitlab.io/pup-filter/pup-filter-ag.txt" },
  { feature: "malware",    source: "Spam TLDs",             url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/spam-tlds.txt" },
  { feature: "malware",    source: "Dandelion Anti-Malware", url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuard.txt" }
];

const FEATURE_ORDER = ["ads", "tracking", "annoyances", "malware"];
const MALWARE_BLOCK_PRIORITY = 2000000; // must stay above session allowances (see background.js)
const RULES_PER_FILE = 10000;
const MAX_COSMETIC_PER_FEATURE = 60000;
const OUT_DIR = "rules/generated";

const TYPE_MAP = { script:"script", image:"image", stylesheet:"stylesheet", object:"object",
  xmlhttprequest:"xmlhttprequest", subdocument:"sub_frame", ping:"ping", media:"media",
  font:"font", websocket:"websocket", other:"other", document:"main_frame" };
const KNOWN_OPTS = new Set(["third-party","domain","script","image","stylesheet","object",
  "xmlhttprequest","subdocument","ping","media","font","websocket","other","document",
  "match-case","important","popup","genericblock","generichide","elemhide","csp","redirect",
  "redirect-rule","removeparam","all"]);

// Returns a DNR-valid urlFilter, or null if the pattern can't be expressed as one.
function sanitizeUrlFilter(u) {
  if (!u) return null;
  if (/[^\x00-\x7F]/.test(u)) return null;
  if (u.startsWith("||*")) u = u.slice(2);
  if (!u) return null;
  let s = u;
  if (s.startsWith("||")) s = s.slice(2);
  else if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  if (s.includes("|")) return null;
  return u;
}

// DNR initiatorDomains must be canonical, lowercase domains.
function cleanDomains(list) {
  const out = [];
  for (let d of list) {
    d = d.toLowerCase();
    if (!d) continue;
    if (/[^a-z0-9.\-]/.test(d)) continue;
    if (!/[a-z0-9]/.test(d)) continue;
    out.push(d);
  }
  return out;
}

function splitOptions(p) {
  if (p.length > 2 && p.startsWith("/") && p.endsWith("/")) return { pattern: p, options: "" };
  const d = p.lastIndexOf("$");
  if (d === -1) return { pattern: p, options: "" };
  const a = p.slice(d + 1);
  if (a === "" || a.includes("/")) return { pattern: p, options: "" };
  const ok = a.split(",").every(t => KNOWN_OPTS.has((t.startsWith("~") ? t.slice(1) : t).split("=")[0]));
  if (!ok) return { pattern: p, options: "" };
  return { pattern: p.slice(0, d), options: a };
}

// Parse an EasyList/AdGuard list into { network:[{priority,action,condition}], cosmetic:[{domains,selector}] }.
function parseList(text) {
  const network = [], cosmetic = [];
  for (const raw of String(text).split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("!") || line.startsWith("[")) continue;
    const cm = line.match(/^([^#]*)##(.+)$/);
    if (cm && !line.includes("://")) {
      const domains = cm[1] ? cm[1].split(",").map(d => d.trim()).filter(Boolean) : [];
      cosmetic.push({ domains, selector: cm[2].trim() });
      continue;
    }
    if (line.includes("#@#") || line.includes("#?#")) continue;
    if (line.startsWith("#")) continue;

    const isException = line.startsWith("@@");
    const body = isException ? line.slice(2) : line;
    const { pattern, options } = splitOptions(body);
    const isRegex = pattern.length > 2 && pattern.startsWith("/") && pattern.endsWith("/");

    const condition = {};
    const rt = new Set(), et = new Set();
    let inc = null, exc = null, dropRule = false;
    for (const opt of options.split(",").filter(Boolean)) {
      const neg = opt.startsWith("~");
      const key = (neg ? opt.slice(1) : opt).split("=")[0];
      const val = opt.includes("=") ? opt.split("=")[1] : null;
      if (TYPE_MAP[key]) (neg ? et : rt).add(TYPE_MAP[key]);
      else if (key === "third-party") condition.domainType = neg ? "firstParty" : "thirdParty";
      else if (key === "domain" && val) {
        const i = [], e = [];
        for (const d of val.split("|")) { if (!d) continue; d.startsWith("~") ? e.push(d.slice(1)) : i.push(d); }
        if (i.length) { inc = cleanDomains(i); if (!inc.length) dropRule = true; }
        if (e.length) { const ce = cleanDomains(e); exc = ce.length ? ce : null; }
      }
    }
    if (dropRule) continue;

    if (isRegex) continue; // RE2 can't be validated offline; runtime dynamic engine handles regex
    if (pattern.startsWith("/") && pattern.endsWith("/")) continue;
    const uf = sanitizeUrlFilter(pattern);
    if (!uf) continue;
    condition.urlFilter = uf;

    if (rt.size) condition.resourceTypes = [...rt];
    if (et.size) condition.excludedResourceTypes = [...et];
    if (inc && inc.length) condition.initiatorDomains = inc;
    if (exc && exc.length) condition.excludedInitiatorDomains = exc;

    network.push({ priority: isException ? 2 : 1, action: { type: isException ? "allow" : "block" }, condition });
  }
  return { network, cosmetic };
}

function dedupeCosmetic(list) {
  const seen = new Set(), out = [];
  for (const c of list) {
    const key = (c.domains || []).join(",") + "##" + c.selector;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}

async function main() {
  // feature -> { rules: [{priority,action,condition,__source}], cosmetic: [...] }
  const featureData = {};
  for (const feature of FEATURE_ORDER) featureData[feature] = { rules: [], cosmetic: [] };

  for (const l of LISTS) {
    process.stdout.write(`Fetching ${l.source} (${l.feature})... `);
    let res;
    try { res = await fetch(l.url, { cache: "no-cache" }); }
    catch (e) { console.log(`FAILED (${e.message})`); continue; }
    if (!res.ok) { console.log(`FAILED (${res.status})`); continue; }
    const text = await res.text();
    const { network, cosmetic } = parseList(text);
    console.log(`${network.length} rules, ${cosmetic.length} cosmetic`);
    const fd = featureData[l.feature];
    for (const r of network) { r.__source = l.source; fd.rules.push(r); }
    for (const c of cosmetic) fd.cosmetic.push(c);
  }

  const totalRules = FEATURE_ORDER.reduce((n, f) => n + featureData[f].rules.length, 0);
  if (!totalRules) {
    console.error("No rules produced (all fetches failed?). Manifest left unchanged.");
    process.exit(1);
  }

  if (!existsSync(OUT_DIR)) await mkdir(OUT_DIR, { recursive: true });

  let idCounter = 1;
  const ruleResources = [];
  const metadata = [];

  for (const feature of FEATURE_ORDER) {
    const fd = featureData[feature];

    // Per-feature static rule files with globally-unique ids.
    for (let offset = 0, index = 0; offset < fd.rules.length; offset += RULES_PER_FILE, index += 1) {
      const chunk = fd.rules.slice(offset, offset + RULES_PER_FILE);
      const clean = chunk.map(r => ({
        id: idCounter++,
        // Malware/phishing must beat session allowances (allow-images etc.), so
        // security stays enforced even in reading mode. Other features use the
        // normal band (block=1, allow/exception=2).
        priority: feature === "malware"
          ? (r.action.type === "allow" ? MALWARE_BLOCK_PRIORITY + 1 : MALWARE_BLOCK_PRIORITY)
          : r.priority,
        action: r.action,
        condition: r.condition
      }));
      const id = `${feature}_static_${index}`;
      const path = `${OUT_DIR}/${id}.json`;
      await writeFile(path, JSON.stringify(clean));
      metadata.push({
        id, feature,
        source: [...new Set(chunk.map(r => r.__source))].join(" + "),
        sourceLocation: "remote-build",
        index,
        count: clean.length,
        allowIds: clean.filter(r => r.action.type === "allow").map(r => r.id)
      });
      ruleResources.push({ id, enabled: false, path });
    }

    // Per-feature cosmetic file (always written so background fetch never 404s).
    const cos = dedupeCosmetic(fd.cosmetic).slice(0, MAX_COSMETIC_PER_FEATURE);
    await writeFile(`${OUT_DIR}/cosmetic-${feature}.json`, JSON.stringify(cos));
  }

  await writeFile(`${OUT_DIR}/ruleset-metadata.json`, JSON.stringify({ rulesets: metadata }, null, 2) + "\n");

  // Rewrite manifest: preserve hand-maintained core_* seeds + backup, replace generated.
  const manifest = JSON.parse(await readFile("manifest.json", "utf8"));
  const preserved = (manifest.declarative_net_request?.rule_resources || [])
    .filter(r => !/_static_/.test(r.id));
  manifest.declarative_net_request = { rule_resources: [...preserved, ...ruleResources] };
  await writeFile("manifest.json", JSON.stringify(manifest, null, 2) + "\n");

  const perFeature = FEATURE_ORDER.map(f => {
    const files = metadata.filter(m => m.feature === f);
    const rules = files.reduce((n, m) => n + m.count, 0);
    return `${f}: ${rules} rules / ${files.length} files`;
  }).join(", ");
  console.log(`\nDone. ${totalRules} rules -> ${ruleResources.length} generated rulesets.`);
  console.log(perFeature);
  console.log("All generated rulesets ship disabled; enabled at runtime by priority within the static budget.");
  console.log("Reload the extension at chrome://extensions after building.");
}

main().catch(e => { console.error(e); process.exit(1); });
