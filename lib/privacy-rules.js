export const PRIVACY_RULE_ID_START = 2_000_000;
export const FILTER_RULE_ID_MAX = 29_000;
export const SESSION_RULE_ID_START = 4_000_000;

// High-confidence campaign/click identifiers that are normally safe to remove
// from top-level navigations, including same-site links.
export const NAVIGATION_TRACKING_PARAMS = Object.freeze([
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
  "gclid", "dclid", "gbraid", "wbraid", "fbclid", "msclkid", "twclid", "ttclid",
  "li_fat_id", "igshid", "mc_cid", "mc_eid", "mkt_tok", "vero_conv", "vero_id",
  "oly_anon_id", "oly_enc_id", "rb_clickid", "wickedid", "epik", "irclickid",
  "_hsenc", "_hsmi", "hsCtaTracking", "s_cid", "yclid", "gad_source", "gad_campaignid",

  // --- added 2.3.0 -------------------------------------------------------------
  // Click identifiers are now the main cross-site join key: third-party cookies
  // are gone, so attribution has moved into the URL itself. Every name below is a
  // vendor campaign/click id with no functional role in page routing.
  "srsltid",                                        // Google Shopping (very widespread)
  "gclsrc", "_gl",                                  // Google Ads source / GA cross-domain linker
  "utm_creative_format", "utm_marketing_tactic",    // GA4 additions
  "ef_id", "s_kwcid",                               // Adobe Advertising / Google Ads keyword id
  "mtm_source", "mtm_medium", "mtm_campaign", "mtm_keyword", "mtm_content",
  "mtm_cid", "mtm_group", "mtm_placement",          // Matomo
  "pk_campaign", "pk_kwd", "pk_source", "pk_medium", "pk_content", // Piwik (legacy Matomo)
  "_openstat",                                      // Yandex
  "fb_action_ids", "fb_action_types", "fb_ref", "sfnsn", // Meta
  "guccounter", "guce_referrer", "guce_referrer_sig",   // Yahoo/Oath consent relay
  "rdt_cid",                                        // Reddit Ads
  "sc_cid",                                         // Snapchat
  "_bhlid",                                         // beehiiv newsletters
  "vgo_ee",                                         // ActiveCampaign (encoded email!)
  "wt_mc", "wt_zmc",                                // Webtrekk
  "xtor",                                           // AT Internet
  "at_medium", "at_campaign",                       // AT Internet / BBC
  "awc", "tduid", "cjevent", "irgwc",               // Awin, TradeDoubler, CJ, Impact
  "ranMID", "ranEAID", "ranSiteID"                  // Rakuten
]);

// Broader identifiers are only stripped from third-party subresources or
// cross-site links because names such as `ref_url` and `adid` can be functional
// on a site's own navigation routes.
// Names below are deliberately NOT in the navigation list. Each is either short
// enough to collide with a site's own routing (`si`, `ttc`, `cmpid`) or genuinely
// functional on some first-party paths (`ref_url`, `extid`), so they are stripped
// only from third-party subresources and cross-site links, where no first-party
// route depends on them.
export const TRACKING_PARAMS = Object.freeze([
  ...NAVIGATION_TRACKING_PARAMS,
  "scid", "spm", "ref_src", "ref_url", "campaignid", "adgroupid", "adid",
  "si", "ttc", "tt_medium", "tt_content", "cmpid", "ncid", "extid",
  "pcrid", "mcrid", "clickid", "trk_contact", "trk_msg", "trk_module"
]);

// `webtransport`, `webbundle` and `csp_report` are Chromium DNR resource types that
// the classic twelve-type list predates. They matter because each is a live
// exfiltration channel that a rule limited to xmlhttprequest/websocket never sees:
//   webtransport - HTTP/3 datagram streams, an increasingly common beacon transport
//   webbundle    - a bundle can carry subresources that never appear as top-level
//                  requests, so filtering only the outer request misses its contents
//   csp_report   - report-uri/report-to POSTs double as a side channel
// test/validate-rules.mjs already accepted all three; no rule had ever used them.
const REQUEST_TYPES = [
  "main_frame", "sub_frame", "script", "image", "stylesheet", "object",
  "xmlhttprequest", "ping", "media", "font", "websocket",
  "webtransport", "webbundle", "csp_report", "other"
];
const SANITIZABLE_SUBRESOURCE_TYPES = [
  "sub_frame", "script", "image", "stylesheet", "object",
  "xmlhttprequest", "ping", "media", "font", "webbundle", "other"
];

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function paramRegex(params) {
  const names = params.map(escapeRegex);
  return `^https?://.*[?&](${names.join("|")})=`;
}

export function buildPrivacyRules(settings) {
  const rules = [];
  let id = PRIVACY_RULE_ID_START;

  if (settings.stripTrackingParams && settings.antiTracking) {
    rules.push({
      id: id++,
      priority: 3_000,
      action: {
        type: "redirect",
        redirect: { transform: { queryTransform: { removeParams: [...NAVIGATION_TRACKING_PARAMS] } } }
      },
      condition: { regexFilter: paramRegex(NAVIGATION_TRACKING_PARAMS), resourceTypes: ["main_frame"] }
    });
    rules.push({
      id: id++,
      priority: 3_000,
      action: {
        type: "redirect",
        redirect: { transform: { queryTransform: { removeParams: [...TRACKING_PARAMS] } } }
      },
      condition: {
        regexFilter: paramRegex(TRACKING_PARAMS),
        resourceTypes: SANITIZABLE_SUBRESOURCE_TYPES,
        domainType: "thirdParty"
      }
    });
  }

  if (settings.privacySignals && settings.antiTracking) {
    rules.push({
      id: id++,
      priority: 2_500,
      action: {
        type: "modifyHeaders",
        requestHeaders: [
          { header: "DNT", operation: "set", value: "1" },
          { header: "Sec-GPC", operation: "set", value: "1" }
        ]
      },
      condition: { urlFilter: "|http", resourceTypes: REQUEST_TYPES }
    });
  }

  return rules;
}

export function isPrivacyRuleId(id) {
  return Number(id) >= PRIVACY_RULE_ID_START && Number(id) < SESSION_RULE_ID_START;
}
