import { registrableApprox } from "./domain-utils.js";

export const TRACKER_CATEGORIES = Object.freeze({
  advertising: { name: "Advertising", description: "Ad delivery, retargeting, bidding, attribution, and conversion measurement." },
  site_analytics: { name: "Site Analytics", description: "Audience, performance, product, and usage analytics." },
  social_media: { name: "Social Media", description: "Social widgets, embedded content, audience matching, and social advertising." },
  consent_management: { name: "Consent Management", description: "Cookie and consent-management platforms." },
  customer_interaction: { name: "Customer Interaction", description: "Chat, support, CRM, surveys, personalization, and marketing automation." },
  audio_video: { name: "Audio / Video", description: "Embedded media players, audience measurement, and streaming support." },
  hosting: { name: "Hosting / CDN", description: "Content delivery, hosting, tag serving, and infrastructure." },
  fingerprinting: { name: "Fingerprinting", description: "Signals or scripts associated with browser or device fingerprinting." },
  error_reporting: { name: "Error Reporting", description: "Crash, performance, logging, and application monitoring." },
  utilities: { name: "Utilities", description: "Tag managers and technical utilities that can load other services." },
  malware: { name: "Malware", description: "Known or suspected malware destinations from enabled security lists." },
  miscellaneous: { name: "Miscellaneous", description: "Recognized data-exchange activity without a more precise local classification." }
});

const PROFILES = [
  ["google-analytics.com", "Google Analytics", "Google", "site_analytics"],
  ["googletagmanager.com", "Google Tag Manager", "Google", "utilities"],
  ["googletagservices.com", "Google Publisher Tags", "Google", "advertising"],
  ["doubleclick.net", "DoubleClick", "Google", "advertising"],
  ["googleadservices.com", "Google Ads", "Google", "advertising"],
  ["googlesyndication.com", "Google AdSense", "Google", "advertising"],
  ["google.com/pagead", "Google Ads Measurement", "Google", "advertising"],
  ["google.com/ccm", "Google Campaign Manager", "Google", "advertising"],
  ["facebook.net", "Meta Pixel", "Meta", "social_media"],
  ["facebook.com/tr", "Meta Pixel", "Meta", "advertising"],
  ["connect.facebook.net", "Meta SDK", "Meta", "social_media"],
  ["instagram.com", "Instagram Embed", "Meta", "social_media"],
  ["bat.bing.com", "Microsoft Advertising UET", "Microsoft", "advertising"],
  ["clarity.ms", "Microsoft Clarity", "Microsoft", "site_analytics"],
  ["linkedin.com/insight", "LinkedIn Insight Tag", "Microsoft", "advertising"],
  ["licdn.com", "LinkedIn Services", "Microsoft", "social_media"],
  ["amazon-adsystem.com", "Amazon Ads", "Amazon", "advertising"],
  ["amazon.com/aan", "Amazon Attribution", "Amazon", "advertising"],
  ["ads-twitter.com", "X Ads", "X Corp.", "advertising"],
  ["analytics.twitter.com", "X Analytics", "X Corp.", "site_analytics"],
  ["platform.twitter.com", "X Widgets", "X Corp.", "social_media"],
  ["analytics.tiktok.com", "TikTok Analytics", "ByteDance", "site_analytics"],
  ["business-api.tiktok.com", "TikTok Business", "ByteDance", "advertising"],
  ["snap.licdn.com", "LinkedIn Insight", "Microsoft", "advertising"],
  ["sc-static.net", "Snap Pixel", "Snap", "advertising"],
  ["tr.snapchat.com", "Snap Pixel", "Snap", "advertising"],
  ["ct.pinterest.com", "Pinterest Tag", "Pinterest", "advertising"],
  ["analytics.pinterest.com", "Pinterest Analytics", "Pinterest", "site_analytics"],
  ["ads.reddit.com", "Reddit Ads", "Reddit", "advertising"],
  ["events.redditmedia.com", "Reddit Events", "Reddit", "site_analytics"],
  ["criteo.com", "Criteo", "Criteo", "advertising"],
  ["criteo.net", "Criteo", "Criteo", "advertising"],
  ["taboola.com", "Taboola", "Taboola", "advertising"],
  ["outbrain.com", "Outbrain", "Outbrain", "advertising"],
  ["quantserve.com", "Quantcast", "Quantcast", "advertising"],
  ["quantcount.com", "Quantcast Measure", "Quantcast", "site_analytics"],
  ["scorecardresearch.com", "Comscore ScorecardResearch", "Comscore", "site_analytics"],
  ["demdex.net", "Adobe Audience Manager", "Adobe", "advertising"],
  ["omtrdc.net", "Adobe Analytics", "Adobe", "site_analytics"],
  ["2o7.net", "Adobe Analytics", "Adobe", "site_analytics"],
  ["hotjar.com", "Hotjar", "Hotjar", "site_analytics"],
  ["hotjar.io", "Hotjar", "Hotjar", "site_analytics"],
  ["mixpanel.com", "Mixpanel", "Mixpanel", "site_analytics"],
  ["segment.com", "Twilio Segment", "Twilio", "utilities"],
  ["segment.io", "Twilio Segment", "Twilio", "utilities"],
  ["amplitude.com", "Amplitude", "Amplitude", "site_analytics"],
  ["heap.io", "Heap Analytics", "Contentsquare", "site_analytics"],
  ["fullstory.com", "FullStory", "FullStory", "site_analytics"],
  ["newrelic.com", "New Relic", "New Relic", "error_reporting"],
  ["nr-data.net", "New Relic Browser", "New Relic", "error_reporting"],
  ["sentry.io", "Sentry", "Sentry", "error_reporting"],
  ["browser-intake-datadoghq.com", "Datadog RUM", "Datadog", "error_reporting"],
  ["datadoghq-browser-agent.com", "Datadog Browser Agent", "Datadog", "error_reporting"],
  ["logrocket.io", "LogRocket", "LogRocket", "site_analytics"],
  ["mouseflow.com", "Mouseflow", "Mouseflow", "site_analytics"],
  ["crazyegg.com", "Crazy Egg", "Crazy Egg", "site_analytics"],
  ["matomo.cloud", "Matomo Cloud", "Matomo", "site_analytics"],
  ["plausible.io", "Plausible Analytics", "Plausible Insights", "site_analytics"],
  ["hubspot.com", "HubSpot", "HubSpot", "customer_interaction"],
  ["hs-analytics.net", "HubSpot Analytics", "HubSpot", "site_analytics"],
  ["hs-scripts.com", "HubSpot Scripts", "HubSpot", "customer_interaction"],
  ["intercom.io", "Intercom", "Intercom", "customer_interaction"],
  ["intercomcdn.com", "Intercom", "Intercom", "customer_interaction"],
  ["zendesk.com", "Zendesk", "Zendesk", "customer_interaction"],
  ["zdassets.com", "Zendesk Assets", "Zendesk", "customer_interaction"],
  ["salesforce.com", "Salesforce", "Salesforce", "customer_interaction"],
  ["pardot.com", "Marketing Cloud Account Engagement", "Salesforce", "customer_interaction"],
  ["marketo.net", "Adobe Marketo", "Adobe", "customer_interaction"],
  ["optimizely.com", "Optimizely", "Optimizely", "site_analytics"],
  ["vwo.com", "VWO", "Wingify", "site_analytics"],
  ["onetrust.com", "OneTrust", "OneTrust", "consent_management"],
  ["cookielaw.org", "OneTrust Cookie Consent", "OneTrust", "consent_management"],
  ["cookiebot.com", "Cookiebot", "Usercentrics", "consent_management"],
  ["usercentrics.eu", "Usercentrics", "Usercentrics", "consent_management"],
  ["trustarc.com", "TrustArc", "TrustArc", "consent_management"],
  ["quantcast.mgr.consensu.org", "Quantcast Choice", "Quantcast", "consent_management"],
  ["didomi.io", "Didomi", "Didomi", "consent_management"],
  ["consentmanager.net", "consentmanager", "consentmanager", "consent_management"],
  ["brightcove.com", "Brightcove Player", "Brightcove", "audio_video"],
  ["jwplayer.com", "JW Player", "JWP", "audio_video"],
  ["vimeo.com", "Vimeo Embed", "Vimeo", "audio_video"],
  ["youtube.com/embed", "YouTube Embed", "Google", "audio_video"],
  ["fingerprint.com", "Fingerprint", "Fingerprint", "fingerprinting"],
  ["fpjs.io", "FingerprintJS", "Fingerprint", "fingerprinting"],
  ["iovation.com", "iovation", "TransUnion", "fingerprinting"],
  ["perimeterx.net", "HUMAN / PerimeterX", "HUMAN Security", "fingerprinting"],
  ["cloudflareinsights.com", "Cloudflare Web Analytics", "Cloudflare", "site_analytics"],
  ["cdnjs.cloudflare.com", "Cloudflare CDN", "Cloudflare", "hosting"],
  ["akamaihd.net", "Akamai CDN", "Akamai", "hosting"],
  ["fastly.net", "Fastly CDN", "Fastly", "hosting"],
  ["adsrvr.org", "The Trade Desk", "The Trade Desk", "advertising"],
  ["adnxs.com", "Xandr (AppNexus)", "Microsoft", "advertising"],
  ["rubiconproject.com", "Magnite (Rubicon)", "Magnite", "advertising"],
  ["pubmatic.com", "PubMatic", "PubMatic", "advertising"],
  ["openx.net", "OpenX", "OpenX", "advertising"],
  ["casalemedia.com", "Index Exchange", "Index Exchange", "advertising"],
  ["indexww.com", "Index Exchange", "Index Exchange", "advertising"],
  ["smartadserver.com", "Equativ (Smart)", "Equativ", "advertising"],
  ["adform.net", "Adform", "Adform", "advertising"],
  ["3lift.com", "TripleLift", "TripleLift", "advertising"],
  ["sharethrough.com", "Sharethrough", "Sharethrough", "advertising"],
  ["yieldmo.com", "Yieldmo", "Yieldmo", "advertising"],
  ["gumgum.com", "GumGum", "GumGum", "advertising"],
  ["media.net", "Media.net", "Media.net", "advertising"],
  ["bidswitch.net", "BidSwitch", "IPONWEB", "advertising"],
  ["teads.tv", "Teads", "Teads", "advertising"],
  ["moatads.com", "Oracle Moat", "Oracle", "advertising"],
  ["adsafeprotected.com", "Integral Ad Science", "IAS", "advertising"],
  ["doubleverify.com", "DoubleVerify", "DoubleVerify", "advertising"],
  ["adroll.com", "AdRoll", "NextRoll", "advertising"],
  ["advertising.com", "Yahoo Advertising", "Yahoo", "advertising"],
  ["yahoo.com", "Yahoo", "Yahoo", "advertising"],
  ["serving-sys.com", "Amazon (Sizmek)", "Amazon", "advertising"],
  ["contextweb.com", "PulsePoint", "PulsePoint", "advertising"],
  ["adcolony.com", "AdColony", "DigitalTurbine", "advertising"],
  ["applovin.com", "AppLovin", "AppLovin", "advertising"],
  ["inmobi.com", "InMobi", "InMobi", "advertising"],
  ["unrulymedia.com", "Unruly", "Nexxen", "advertising"],
  ["spotxchange.com", "SpotX", "Magnite", "advertising"],
  ["spotx.tv", "SpotX", "Magnite", "advertising"],
  ["mathtag.com", "MediaMath", "MediaMath", "advertising"],
  ["bluekai.com", "Oracle BlueKai", "Oracle", "advertising"],
  ["rlcdn.com", "LiveRamp", "LiveRamp", "advertising"],
  ["agkn.com", "Neustar AdAdvisor", "TransUnion", "advertising"],
  ["everesttech.net", "Adobe Advertising", "Adobe", "advertising"],
  ["adsymptotic.com", "Drawbridge", "LinkedIn", "advertising"],
  ["crwdcntrl.net", "Lotame", "Lotame", "advertising"],
  ["tapad.com", "Tapad", "Experian", "advertising"],
  ["taboola.com", "Taboola", "Taboola", "advertising"],
  ["zemanta.com", "Zemanta", "Outbrain", "advertising"],
  ["revcontent.com", "Revcontent", "Revcontent", "advertising"],
  ["mgid.com", "MGID", "MGID", "advertising"],
  ["chartbeat.com", "Chartbeat", "Chartbeat", "site_analytics"],
  ["parsely.com", "Parse.ly", "Automattic", "site_analytics"],
  ["cxense.com", "Piano (Cxense)", "Piano", "site_analytics"],
  ["mparticle.com", "mParticle", "mParticle", "utilities"],
  ["tealium.com", "Tealium", "Tealium", "utilities"],
  ["tiqcdn.com", "Tealium iQ", "Tealium", "utilities"],
  ["ensighten.com", "Ensighten", "Cheq", "utilities"],
  ["branch.io", "Branch", "Branch", "utilities"],
  ["appsflyer.com", "AppsFlyer", "AppsFlyer", "advertising"],
  ["adjust.com", "Adjust", "AppLovin", "advertising"],
  ["kochava.com", "Kochava", "Kochava", "advertising"],
  ["braze.com", "Braze", "Braze", "customer_interaction"],
  ["iterable.com", "Iterable", "Iterable", "customer_interaction"],
  ["klaviyo.com", "Klaviyo", "Klaviyo", "customer_interaction"],
  ["mailchimp.com", "Mailchimp", "Intuit", "customer_interaction"],
  ["list-manage.com", "Mailchimp", "Intuit", "customer_interaction"],
  ["drift.com", "Drift", "Salesloft", "customer_interaction"],
  ["tawk.to", "tawk.to", "tawk.to", "customer_interaction"],
  ["livechatinc.com", "LiveChat", "Text", "customer_interaction"],
  ["olark.com", "Olark", "Olark", "customer_interaction"],
  ["qualtrics.com", "Qualtrics", "Qualtrics", "customer_interaction"],
  ["typekit.net", "Adobe Fonts", "Adobe", "hosting"],
  ["fonts.googleapis.com", "Google Fonts", "Google", "hosting"],
  ["fonts.gstatic.com", "Google Fonts", "Google", "hosting"],
  ["gstatic.com", "Google Static", "Google", "hosting"],
  ["jsdelivr.net", "jsDelivr CDN", "jsDelivr", "hosting"],
  ["unpkg.com", "unpkg CDN", "unpkg", "hosting"],
  ["bootstrapcdn.com", "BootstrapCDN", "StackPath", "hosting"],
  ["cloudfront.net", "Amazon CloudFront", "Amazon", "hosting"],
  ["azureedge.net", "Azure CDN", "Microsoft", "hosting"],
  ["bugsnag.com", "Bugsnag", "SmartBear", "error_reporting"],
  ["rollbar.com", "Rollbar", "Rollbar", "error_reporting"],
  ["raygun.io", "Raygun", "Raygun", "error_reporting"],
  ["pingdom.net", "Pingdom", "SolarWinds", "error_reporting"],
  ["speedcurve.com", "SpeedCurve", "SpeedCurve", "error_reporting"],
  ["cookieyes.com", "CookieYes", "CookieYes", "consent_management"],
  ["osano.com", "Osano", "Osano", "consent_management"],
  ["termly.io", "Termly", "Termly", "consent_management"],
  ["sourcepoint.com", "Sourcepoint", "Sourcepoint", "consent_management"],
  ["privacy-center.org", "Axeptio", "Axeptio", "consent_management"],
  ["seznam.cz", "Seznam", "Seznam", "advertising"],
  ["yandex.ru", "Yandex Metrica", "Yandex", "site_analytics"],
  ["mc.yandex.ru", "Yandex Metrica", "Yandex", "site_analytics"],
  ["vk.com", "VK", "VK", "social_media"],
  ["tiktokcdn.com", "TikTok CDN", "ByteDance", "hosting"],
  ["bytedance.com", "ByteDance", "ByteDance", "advertising"],
  ["shopify.com", "Shopify", "Shopify", "utilities"],
  ["cdn.shopify.com", "Shopify CDN", "Shopify", "hosting"],
  ["stripe.com", "Stripe", "Stripe", "customer_interaction"],
  ["stripe.network", "Stripe (fraud)", "Stripe", "fingerprinting"],
  ["paypal.com", "PayPal", "PayPal", "customer_interaction"],
  ["recaptcha.net", "Google reCAPTCHA", "Google", "utilities"],
  ["hcaptcha.com", "hCaptcha", "hCaptcha", "utilities"],
  ["arkoselabs.com", "Arkose Labs", "Arkose Labs", "fingerprinting"],
  ["captcha-delivery.com", "DataDome", "DataDome", "fingerprinting"],
  ["cdn-cgi", "Cloudflare Challenge", "Cloudflare", "utilities"],
  ["adobedtm.com", "Adobe Dynamic Tag Mgmt", "Adobe", "utilities"],
  ["sc.omtrdc.net", "Adobe Analytics", "Adobe", "site_analytics"],
  ["krxd.net", "Salesforce Krux", "Salesforce", "advertising"],
  ["exelator.com", "Nielsen eXelate", "Nielsen", "advertising"],
  ["imrworldwide.com", "Nielsen", "Nielsen", "site_analytics"],
  ["adobe.io", "Adobe Services", "Adobe", "utilities"],
  ["snapchat.com", "Snapchat", "Snap", "social_media"],
  ["pinimg.com", "Pinterest CDN", "Pinterest", "hosting"],
  ["redditstatic.com", "Reddit Static", "Reddit", "hosting"],
  ["twimg.com", "X (Twitter) CDN", "X Corp.", "hosting"],
  ["fbcdn.net", "Meta CDN", "Meta", "hosting"],
  ["cdninstagram.com", "Instagram CDN", "Meta", "hosting"]
].map(([match, name, organization, category]) => ({ match, name, organization, category }));

const HEURISTICS = [
  [/fingerprint|fpjs|canvas[-_.]?print|deviceid|device-id/i, "fingerprinting"],
  [/doubleclick|adservice|adserver|adnxs|adsystem|adform|advertis|retarget|pixel\.facebook|conversion/i, "advertising"],
  [/analytics|metric|telemetry|measure|collect|stats|insight|beacon|events/i, "site_analytics"],
  [/consent|cookiebot|cookielaw|cmp\.|privacy-mgmt|trustarc|onetrust|didomi|usercentrics/i, "consent_management"],
  [/intercom|zendesk|livechat|hubspot|salesforce|marketo|pardot|survey|feedback/i, "customer_interaction"],
  [/player|video|stream|brightcove|jwplayer|vimeo|youtube/i, "audio_video"],
  [/sentry|newrelic|datadog|bugsnag|rollbar|logrocket|error|crash/i, "error_reporting"],
  [/tagmanager|tag-manager|tealium|ensighten/i, "utilities"],
  [/facebook|instagram|twitter|linkedin|pinterest|reddit|tiktok|snapchat/i, "social_media"]
];

function hostnameFromUrl(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function matchProfile(url, host) {
  const lower = String(url || "").toLowerCase();
  for (const profile of PROFILES) {
    const needle = profile.match.toLowerCase();
    if (needle.includes("/")) {
      if (lower.includes(needle)) return profile;
    } else if (host === needle || host.endsWith(`.${needle}`)) {
      return profile;
    }
  }
  return null;
}

export function classifyRequest(url, { sourceUrl = "", blocked = false, malware = false } = {}) {
  const host = hostnameFromUrl(url);
  if (!host) return null;
  const sourceHost = hostnameFromUrl(sourceUrl);
  const thirdParty = sourceHost ? registrableApprox(host) !== registrableApprox(sourceHost) : true;
  const profile = matchProfile(url, host);

  let category = malware ? "malware" : profile?.category;
  if (!category) {
    const haystack = `${host}${new URL(url).pathname}`;
    for (const [pattern, key] of HEURISTICS) {
      if (pattern.test(haystack)) { category = key; break; }
    }
  }
  if (!category && !blocked) return null;
  category ||= "miscellaneous";

  return {
    key: profile ? `${profile.organization}:${profile.name}` : host,
    name: profile?.name || host,
    organization: profile?.organization || registrableApprox(host),
    category,
    categoryName: TRACKER_CATEGORIES[category]?.name || "Miscellaneous",
    hostname: host,
    thirdParty,
    blocked: Boolean(blocked),
    url: String(url).slice(0, 1500)
  };
}

export function classifyDestination(url) {
  const host = hostnameFromUrl(url);
  if (!host) return null;
  const profile = matchProfile(url, host);
  if (!profile) return null;
  return {
    name: profile.name,
    organization: profile.organization,
    category: profile.category,
    categoryName: TRACKER_CATEGORIES[profile.category]?.name || "Miscellaneous"
  };
}

export function summarizeTrackers(items = []) {
  const merged = new Map();
  for (const item of items) {
    if (!item) continue;
    const previous = merged.get(item.key);
    if (!previous) {
      merged.set(item.key, { ...item, count: 1, blockedCount: item.blocked ? 1 : 0 });
    } else {
      previous.count += 1;
      if (item.blocked) previous.blockedCount += 1;
      previous.blocked = previous.blocked || item.blocked;
    }
  }
  const trackers = [...merged.values()].sort((a, b) =>
    Number(b.blocked) - Number(a.blocked) || b.count - a.count || a.name.localeCompare(b.name));
  const categories = {};
  for (const tracker of trackers) categories[tracker.category] = (categories[tracker.category] || 0) + 1;
  return {
    trackers,
    categories,
    detected: trackers.length,
    blocked: trackers.filter(t => t.blocked).length
  };
}
