import type { VirusTotalStatus, VirusTotalSummary } from "../scoring/types";

const VT_API_BASE = "https://www.virustotal.com/api/v3/domains/";
const VT_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const VT_ERROR_CACHE_TTL_MS = 5 * 60 * 1000;
const VT_MIN_REQUEST_INTERVAL_MS = 16_000;

type CacheEntry = {
  status: VirusTotalStatus;
  value?: VirusTotalSummary;
  ts: number;
};

const cache = new Map<string, CacheEntry>();
const inFlight = new Map<string, Promise<VirusTotalLookupResult>>();
let lastRequestAt = 0;

export type VirusTotalLookupResult = {
  status: VirusTotalStatus;
  summary?: VirusTotalSummary;
};

const wait = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

const ensureRateLimit = async () => {
  const elapsed = Date.now() - lastRequestAt;
  if (elapsed < VT_MIN_REQUEST_INTERVAL_MS) {
    await wait(VT_MIN_REQUEST_INTERVAL_MS - elapsed);
  }
  lastRequestAt = Date.now();
};

const parseSummary = (payload: unknown): VirusTotalSummary | null => {
  const data = payload as {
    data?: {
      attributes?: {
        last_analysis_stats?: {
          malicious?: number;
          suspicious?: number;
          harmless?: number;
          undetected?: number;
        };
        reputation?: number;
        last_analysis_date?: number;
      };
    };
  };

  const stats = data.data?.attributes?.last_analysis_stats;
  if (!stats) {
    return null;
  }

  return {
    malicious: Number(stats.malicious ?? 0),
    suspicious: Number(stats.suspicious ?? 0),
    harmless: Number(stats.harmless ?? 0),
    undetected: Number(stats.undetected ?? 0),
    reputation: Number(data.data?.attributes?.reputation ?? 0),
    lastAnalysisDate: Number(data.data?.attributes?.last_analysis_date ?? 0)
  };
};

export async function getDomainSummary(
  domain: string,
  apiKey: string
): Promise<VirusTotalLookupResult> {
  const normalizedKey = apiKey.trim();
  if (!domain || !normalizedKey) {
    return { status: "no_data" };
  }

  const cacheEntry = cache.get(domain);
  const cacheTtl =
    cacheEntry?.status === "checked" || cacheEntry?.status === "no_data"
      ? VT_CACHE_TTL_MS
      : VT_ERROR_CACHE_TTL_MS;
  if (cacheEntry && Date.now() - cacheEntry.ts <= cacheTtl) {
    return { status: cacheEntry.status, summary: cacheEntry.value };
  }

  const running = inFlight.get(domain);
  if (running) {
    return running;
  }

  const request: Promise<VirusTotalLookupResult> = (async (): Promise<VirusTotalLookupResult> => {
    await ensureRateLimit();

    try {
      const response = await fetch(`${VT_API_BASE}${encodeURIComponent(domain)}`, {
        method: "GET",
        headers: { "x-apikey": normalizedKey }
      });

      if (!response.ok) {
        const status: VirusTotalStatus = response.status === 404 ? "no_data" : "error";
        cache.set(domain, { status, ts: Date.now() });
        return { status };
      }

      const payload = (await response.json()) as unknown;
      const summary = parseSummary(payload);
      if (!summary) {
        cache.set(domain, { status: "no_data", ts: Date.now() });
        return { status: "no_data" };
      }

      cache.set(domain, { status: "checked", value: summary, ts: Date.now() });
      return { status: "checked", summary };
    } catch {
      cache.set(domain, { status: "error", ts: Date.now() });
      return { status: "error" };
    } finally {
      inFlight.delete(domain);
    }
  })();

  inFlight.set(domain, request);
  return request;
}
