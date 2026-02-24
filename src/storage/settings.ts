import { normalizeDomain } from "../utils/domains";

export type Settings = {
  enableMaliciousChecks: boolean;
  enableAdsChecks: boolean;
  enableContentChecks: boolean;
  enableTextSample: boolean;
  enableVirusTotal: boolean;
  enableDangerAlerts: boolean;
  sensitivity: number;
  lowMax: number;
  mediumMax: number;
  virusTotalApiKey: string;
  allowlist: string[];
  denylist: string[];
};

export const DEFAULT_SETTINGS: Settings = {
  enableMaliciousChecks: true,
  enableAdsChecks: true,
  enableContentChecks: true,
  enableTextSample: false,
  enableVirusTotal: false,
  enableDangerAlerts: true,
  sensitivity: 1,
  lowMax: 24,
  mediumMax: 59,
  virusTotalApiKey: "",
  allowlist: [],
  denylist: []
};

const SETTINGS_KEY = "settings";

export type DomainParseResult = {
  domains: string[];
  invalid: string[];
};

export function parseDomainLines(text: string): DomainParseResult {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const domains: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();

  for (const entry of lines) {
    if (entry.includes("://") || entry.includes("/")) {
      invalid.push(entry);
      continue;
    }

    const normalized = normalizeDomain(entry);
    if (!normalized) {
      invalid.push(entry);
      continue;
    }

    if (!seen.has(normalized)) {
      domains.push(normalized);
      seen.add(normalized);
    }
  }

  return { domains, invalid };
}

export function normalizeDomainList(values: string[]): string[] {
  const { domains } = parseDomainLines(values.join("\n"));
  return domains;
}

const clamp = (value: number, min: number, max: number) =>
  Math.min(max, Math.max(min, value));

const parseNumber = (value: unknown, fallback: number): number => {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
};

export function normalizeThresholds(input: {
  lowMax: number;
  mediumMax: number;
}): { lowMax: number; mediumMax: number } {
  const lowMax = clamp(Math.round(input.lowMax), 0, 98);
  const mediumMax = clamp(Math.round(input.mediumMax), lowMax + 1, 99);
  return { lowMax, mediumMax };
}

function normalizeSettings(raw: Partial<Settings> | undefined): Settings {
  const lowRaw = parseNumber(raw?.lowMax, DEFAULT_SETTINGS.lowMax);
  const mediumRaw = parseNumber(raw?.mediumMax, DEFAULT_SETTINGS.mediumMax);
  const { lowMax, mediumMax } = normalizeThresholds({ lowMax: lowRaw, mediumMax: mediumRaw });
  const sensitivity = clamp(parseNumber(raw?.sensitivity, DEFAULT_SETTINGS.sensitivity), 0.5, 1.5);
  const allowlist = normalizeDomainList(raw?.allowlist ?? []);
  const allowSet = new Set(allowlist);
  const denylist = normalizeDomainList(raw?.denylist ?? []).filter((domain) => !allowSet.has(domain));

  return {
    ...DEFAULT_SETTINGS,
    ...raw,
    sensitivity,
    lowMax,
    mediumMax,
    virusTotalApiKey:
      typeof raw?.virusTotalApiKey === "string" ? raw.virusTotalApiKey.trim() : "",
    allowlist,
    denylist
  };
}

export async function getSettings(): Promise<Settings> {
  const data = await chrome.storage.local.get(SETTINGS_KEY);
  const stored = data[SETTINGS_KEY] as Partial<Settings> | undefined;
  return normalizeSettings(stored);
}

export async function saveSettings(settings: Settings): Promise<void> {
  await chrome.storage.local.set({ [SETTINGS_KEY]: normalizeSettings(settings) });
}

export async function updateDomainLists(update: {
  allowlist?: string[];
  denylist?: string[];
}): Promise<Settings> {
  const current = await getSettings();

  const nextAllow = update.allowlist ?? current.allowlist;
  const nextDeny = update.denylist ?? current.denylist;

  const allowlist = normalizeDomainList(nextAllow);
  const denylist = normalizeDomainList(nextDeny).filter(
    (domain) => !allowlist.includes(domain)
  );

  const next: Settings = {
    ...current,
    allowlist,
    denylist
  };

  await saveSettings(next);
  return next;
}
