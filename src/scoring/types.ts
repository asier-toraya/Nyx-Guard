export type RiskLevel = "low" | "medium" | "high";

export type ReasonCategory = "malicious" | "ads" | "content" | "system";

export type Reason = {
  id: string;
  title: string;
  detail: string;
  weight: number;
  category: ReasonCategory;
};

export type VirusTotalSummary = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  lastAnalysisDate: number;
};

export type VirusTotalStatus = "checked" | "no_data" | "error";

export type Features = {
  url: string;
  domain: string;
  hasPasswordForm: boolean;
  suspiciousLoginKeywordsFound: string[];
  overlayCount: number;
  hasBlockingOverlay: boolean;
  notificationDarkPatternKeywords: string[];
  adLikeElementsCount: number;
  iframeHiddenCount: number;
  pageTextSample?: string;
  countTrackers: number;
  virusTotalStatus?: VirusTotalStatus;
  virusTotal?: VirusTotalSummary;
};

export type ContentFeatures = Omit<Features, "countTrackers">;

export type DetectionResult = {
  score: number;
  level: RiskLevel;
  reasons: Reason[];
  features: Features;
  domain: string;
  url: string;
  ts: number;
  version: string;
};
