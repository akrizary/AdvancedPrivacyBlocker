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
  "_hsenc", "_hsmi", "hsCtaTracking", "s_cid", "yclid", "gad_source", "gad_campaignid"
]);

// Broader identifiers are only stripped from third-party subresources or
// cross-site links because names such as `ref_url` and `adid` can be functional
// on a site's own navigation routes.
export const TRACKING_PARAMS = Object.freeze([
  ...NAVIGATION_TRACKING_PARAMS,
  "scid", "spm", "ref_src", "ref_url", "campaignid", "adgroupid", "adid"
]);

const REQUEST_TYPES = [
  "main_frame", "sub_frame", "script", "image", "stylesheet", "object",
  "xmlhttprequest", "ping", "media", "font", "websocket", "other"
];
const SANITIZABLE_SUBRESOURCE_TYPES = [
  "sub_frame", "script", "image", "stylesheet", "object",
  "xmlhttprequest", "ping", "media", "font", "other"
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
