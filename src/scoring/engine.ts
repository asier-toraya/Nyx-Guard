import { isPunycodeDomain } from "../utils/domains";
import { ENGINE_VERSION, WEIGHTS } from "./rules";
import type { DetectionResult, Features, Reason, RiskLevel } from "./types";
import type { Settings } from "../storage/settings";

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const applySensitivity = (weight: number, sensitivity: number) => Math.round(weight * sensitivity);

const toLevel = (score: number, settings: Settings): RiskLevel => {
  if (score <= settings.lowMax) {
    return "low";
  }
  if (score <= settings.mediumMax) {
    return "medium";
  }
  return "high";
};

export function evaluate(features: Features, settings: Settings): DetectionResult {
  const reasons: Reason[] = [];
  let score = 0;

  const domain = features.domain;
  const allowlisted = settings.allowlist.includes(domain);
  const denylisted = settings.denylist.includes(domain);

  if (allowlisted) {
    reasons.push({
      id: "allowlist",
      title: "Trusted domain",
      detail: `${domain} is in your allowlist.`,
      weight: WEIGHTS.allowlist,
      category: "system"
    });

    return {
      score: 0,
      level: "low",
      reasons,
      features,
      domain,
      url: features.url,
      ts: Date.now(),
      version: ENGINE_VERSION
    };
  }

  if (denylisted) {
    score += WEIGHTS.denylist;
    reasons.push({
      id: "denylist",
      title: "Blocked domain",
      detail: `${domain} is in your denylist.`,
      weight: WEIGHTS.denylist,
      category: "system"
    });
  }

  if (settings.enableMaliciousChecks) {
    if (isPunycodeDomain(domain)) {
      const weight = applySensitivity(WEIGHTS.punycodeDomain, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "punycode-domain",
        title: "Punycode domain",
        detail: "Domain contains punycode (xn--) labels.",
        weight,
        category: "malicious"
      });
    }

    if (features.hasPasswordForm && features.suspiciousLoginKeywordsFound.length > 0) {
      const weight = applySensitivity(WEIGHTS.suspiciousLogin, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "suspicious-login",
        title: "Suspicious login pattern",
        detail: `Password form with keywords: ${features.suspiciousLoginKeywordsFound.join(", ")}.`,
        weight,
        category: "malicious"
      });
    }
  }

  if (settings.enableContentChecks) {
    if (features.hasBlockingOverlay || features.overlayCount >= 2) {
      const weight = applySensitivity(WEIGHTS.invasiveOverlay, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "invasive-overlay",
        title: "Invasive overlay",
        detail: `Detected ${features.overlayCount} full-screen overlay(s).`,
        weight,
        category: "content"
      });
    }

    if (features.notificationDarkPatternKeywords.length > 0) {
      const weight = applySensitivity(WEIGHTS.popupAbuse, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "popup-abuse",
        title: "Notification pressure",
        detail: `Keywords found: ${features.notificationDarkPatternKeywords.join(", ")}.`,
        weight,
        category: "content"
      });
    }
  }

  if (settings.enableAdsChecks) {
    const trackerCount = features.countTrackers;
    let trackerWeight = 0;
    let trackerLabel = "";

    if (trackerCount >= 10) {
      trackerWeight = WEIGHTS.trackerHigh;
      trackerLabel = "10+";
    } else if (trackerCount >= 5) {
      trackerWeight = WEIGHTS.trackerMedium;
      trackerLabel = "5-9";
    } else if (trackerCount >= 1) {
      trackerWeight = WEIGHTS.trackerLow;
      trackerLabel = "1-4";
    }

    if (trackerWeight > 0) {
      const weight = applySensitivity(trackerWeight, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "tracker-density",
        title: "Tracker density",
        detail: `Matched ${trackerCount} tracker request(s) (${trackerLabel}).`,
        weight,
        category: "ads"
      });
    }

    if (features.adLikeElementsCount >= 5) {
      const adWeight =
        features.adLikeElementsCount >= 12 ? WEIGHTS.adLikeHigh : WEIGHTS.adLikeLow;
      const weight = applySensitivity(adWeight, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "ad-heavy-dom",
        title: "Ad-heavy layout",
        detail: `Detected ${features.adLikeElementsCount} ad-like element(s).`,
        weight,
        category: "ads"
      });
    }
  }

  if (settings.enableMaliciousChecks && features.iframeHiddenCount >= 2) {
    const weight = applySensitivity(WEIGHTS.hiddenIframes, settings.sensitivity);
    score += weight;
    reasons.push({
      id: "hidden-iframes",
      title: "Hidden iframes",
      detail: `Detected ${features.iframeHiddenCount} hidden iframe(s).`,
      weight,
      category: "malicious"
    });
  }

  if (settings.enableVirusTotal && features.virusTotal) {
    const vt = features.virusTotal;

    if (vt.malicious > 0) {
      const baseWeight =
        vt.malicious >= 3 ? WEIGHTS.virusTotalMaliciousHigh : WEIGHTS.virusTotalMaliciousLow;
      const weight = applySensitivity(baseWeight, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "virustotal-malicious",
        title: "VirusTotal malicious verdicts",
        detail: `${vt.malicious} engine(s) flagged this domain as malicious.`,
        weight,
        category: "malicious"
      });
    }

    if (vt.suspicious > 0) {
      const weight = applySensitivity(WEIGHTS.virusTotalSuspicious, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "virustotal-suspicious",
        title: "VirusTotal suspicious verdicts",
        detail: `${vt.suspicious} engine(s) flagged this domain as suspicious.`,
        weight,
        category: "malicious"
      });
    }

    if (vt.reputation < 0) {
      const weight = applySensitivity(WEIGHTS.virusTotalPoorReputation, settings.sensitivity);
      score += weight;
      reasons.push({
        id: "virustotal-reputation",
        title: "Negative VirusTotal reputation",
        detail: `Reputation score: ${vt.reputation}.`,
        weight,
        category: "malicious"
      });
    }
  }

  score = clamp(score, 0, 100);

  return {
    score,
    level: toLevel(score, settings),
    reasons,
    features,
    domain,
    url: features.url,
    ts: Date.now(),
    version: ENGINE_VERSION
  };
}
