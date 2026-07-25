// Run in the extension's service worker console:
//   import("./lib/converter.test.js").then(m => m.runTests())
// Or in a normal page (regex cases use the mock fallback).

import { parseFilterList } from "./converter.js";

let passed = 0, failed = 0;
const results = [];
function assert(cond, msg) {
  if (cond) { passed++; }
  else { failed++; results.push("FAIL: " + msg); }
}
function eq(a, b, msg) { assert(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)})`); }

if (typeof chrome === "undefined" || !chrome.declarativeNetRequest) {
  globalThis.chrome = {
    declarativeNetRequest: {
      isRegexSupported: async ({ regex }) => {
        try { new RegExp(regex); return { isSupported: true }; }
        catch { return { isSupported: false, reason: "syntaxError" }; }
      }
    }
  };
}

export async function runTests() {
  passed = failed = 0; results.length = 0;

  // 1. Basic domain-anchor block rule
  {
    const { network } = await parseFilterList("||doubleclick.net^", 100);
    eq(network.length, 1, "single block rule produced");
    eq(network[0].action.type, "block", "action is block");
    eq(network[0].condition.urlFilter, "||doubleclick.net^", "urlFilter preserved");
  }

  // 2. $third-party option -> domainType
  {
    const { network } = await parseFilterList("||ads.example^$third-party", 200);
    eq(network[0].condition.domainType, "thirdParty", "third-party mapped");
  }

  // 3. $script,image type options
  {
    const { network } = await parseFilterList("||t.example^$script,image", 300);
    eq(network[0].condition.resourceTypes.sort(), ["image", "script"], "resource types mapped");
  }

  // 4. $domain=a.com|~b.com -> initiator include/exclude
  {
    const { network } = await parseFilterList("||x.example^$domain=a.com|~b.com", 400);
    eq(network[0].condition.initiatorDomains, ["a.com"], "initiator include");
    eq(network[0].condition.excludedInitiatorDomains, ["b.com"], "initiator exclude");
  }

  // 5. Exception rule (@@) -> allow with priority 2
  {
    const { network } = await parseFilterList("@@||safe.example^", 500);
    eq(network[0].action.type, "allow", "exception is allow");
    eq(network[0].priority, 2, "exception priority 2");
  }

  // 6. Cosmetic rule split out, not a network rule
  {
    const { network, cosmetic } = await parseFilterList("example.com##.ad-banner", 600);
    eq(network.length, 0, "cosmetic not counted as network");
    eq(cosmetic.length, 1, "one cosmetic rule");
    eq(cosmetic[0].domains, ["example.com"], "cosmetic domain captured");
    eq(cosmetic[0].selector, ".ad-banner", "cosmetic selector captured");
  }

  // 7. Regex filter -> regexFilter, validated
  {
    const { network, regexCount } = await parseFilterList("/\\/adframe\\d+\\./", 700);
    assert(regexCount === 1, "one regex accepted");
    assert(network[0].condition.regexFilter === "\\/adframe\\d+\\.", "regexFilter set");
  }

  // 8. Invalid regex is skipped
  {
    const { network } = await parseFilterList("/ad(frame/", 800); // unbalanced paren
    eq(network.length, 0, "invalid regex skipped");
  }

  // 9. Comments and section headers ignored
  {
    const { network } = await parseFilterList("! comment\n[Adblock Plus 2.0]\n||z.example^", 900);
    eq(network.length, 1, "comments/headers ignored");
  }

  // 10. Broad exception flagged by auditor
  {
    const { flaggedExceptions } = await parseFilterList("@@||tracker.example^$document", 1000);
    assert(flaggedExceptions.length === 1, "broad $document exception flagged");
  }

  // 11. Bare '#' line is skipped, not turned into a rule
  {
    const { network } = await parseFilterList("#", 1100);
    eq(network.length, 0, "bare # skipped");
  }

  // 12. '$' inside a URL path is preserved (not treated as options)
  {
    const { network } = await parseFilterList("||site.com/a$b^", 1200);
    eq(network[0].condition.urlFilter, "||site.com/a$b^", "$ in path preserved");
  }

  // 13. A genuine trailing option still splits correctly
  {
    const { network } = await parseFilterList("||site.com/x$script", 1300);
    eq(network[0].condition.urlFilter, "||site.com/x", "real option split");
    assert(network[0].condition.resourceTypes[0] === "script", "option applied");
  }

  // 14. Empty $domain= does not create an invalid value
  {
    const { network } = await parseFilterList("||q.example^$domain=", 1400);
    eq(network[0].condition.urlFilter, "||q.example^", "empty domain handled");
  }

  // 15. "||*" domain-anchor-wildcard prefix is rewritten to a valid "*" filter
  {
    const { network } = await parseFilterList("||*.exaapi.com^", 1500);
    eq(network.length, 1, "domain-anchor-wildcard kept");
    eq(network[0].condition.urlFilter, "*.exaapi.com^", "||* rewritten to *");
  }

  // 16. Literal mid-pattern pipe is unsupported by DNR -> rule dropped
  {
    const { network } = await parseFilterList("/addyn|*;adtech;", 1600);
    eq(network.length, 0, "mid-pattern pipe dropped");
  }

  const summary = `\n${passed} passed, ${failed} failed`;
  console.log(results.length ? results.join("\n") + summary : "All tests passed." + summary);
  return { passed, failed, failures: results };
}
