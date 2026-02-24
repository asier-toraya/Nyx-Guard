export const ENGINE_VERSION = "0.1.0";

export const WEIGHTS = {
  punycodeDomain: 25,
  suspiciousLogin: 20,
  invasiveOverlay: 15,
  popupAbuse: 10,
  trackerLow: 5,
  trackerMedium: 10,
  trackerHigh: 15,
  adLikeLow: 5,
  adLikeHigh: 10,
  hiddenIframes: 12,
  virusTotalSuspicious: 18,
  virusTotalMaliciousLow: 35,
  virusTotalMaliciousHigh: 55,
  virusTotalPoorReputation: 8,
  denylist: 30,
  allowlist: -100
};

export const DEFAULT_LEVEL_THRESHOLDS = {
  lowMax: 19,
  mediumMax: 49
};
