import { evaluate } from "../scoring/engine";
import type { ContentFeatures, DetectionResult, Features } from "../scoring/types";
import { getSettings, updateDomainLists } from "../storage/settings";
import { isHttpUrl, normalizeDomain } from "../utils/domains";
import { getDomainSummary } from "../integrations/virustotal";

const results = new Map<number, DetectionResult>();
const trackerState = new Map<number, { count: number; lastUrl?: string }>();
const lastContentFeatures = new Map<number, ContentFeatures>();
const recalcTimers = new Map<number, number>();
const alertState = new Map<number, { domain: string; lastAlertTs: number }>();
const RESULT_TTL_MS = 10 * 60 * 1000;
const ALERT_COOLDOWN_MS = 2 * 60 * 1000;
const ALERT_ICON_PATH = "icons/nyx-alert-128.png";
const resultStore = chrome.storage.session ?? chrome.storage.local;

const resultKey = (tabId: number) => `result:${tabId}`;

const toReliabilityScore = (riskScore: number) => Math.max(0, 100 - riskScore);

const setBadgeForResult = async (tabId: number, result: DetectionResult) => {
  const reliability = toReliabilityScore(result.score);
  const badgeText = reliability.toString();
  const badgeColor =
    result.level === "high"
      ? "#f05a5a"
      : result.level === "medium"
        ? "#e5b453"
        : "#2ec27e";

  try {
    await chrome.action.setBadgeText({ tabId, text: badgeText });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
    await chrome.action.setTitle({
      tabId,
      title: `Nyx Guard: fiabilidad ${reliability}/100 | riesgo ${result.score}/100 (${result.level})`
    });
  } catch {
    // Ignore badge errors for tabs that no longer exist.
  }
};

const clearBadgeForTab = async (tabId: number) => {
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
    await chrome.action.setTitle({ tabId, title: "Nyx Guard" });
  } catch {
    // Ignore badge errors for tabs that no longer exist.
  }
};

const clearResult = async (tabId: number) => {
  results.delete(tabId);
  await resultStore.remove(resultKey(tabId));
  await clearBadgeForTab(tabId);
};

const saveResult = async (tabId: number, result: DetectionResult) => {
  results.set(tabId, result);
  await resultStore.set({ [resultKey(tabId)]: result });
  await setBadgeForResult(tabId, result);
};

const loadResult = async (tabId: number): Promise<DetectionResult | null> => {
  const cached = results.get(tabId);
  if (cached && Date.now() - cached.ts <= RESULT_TTL_MS) {
    return cached;
  }

  const data = await resultStore.get(resultKey(tabId));
  const stored = data[resultKey(tabId)] as DetectionResult | undefined;
  if (!stored) {
    return null;
  }

  if (Date.now() - stored.ts > RESULT_TTL_MS) {
    await clearResult(tabId);
    return null;
  }

  results.set(tabId, stored);
  await setBadgeForResult(tabId, stored);
  return stored;
};

const resetTrackerState = (tabId: number, url?: string) => {
  trackerState.set(tabId, { count: 0, lastUrl: url });
  lastContentFeatures.delete(tabId);
  alertState.delete(tabId);
  const timer = recalcTimers.get(tabId);
  if (timer) {
    clearTimeout(timer);
    recalcTimers.delete(tabId);
  }
};

const createDangerNotification = async (
  title: string,
  message: string
): Promise<boolean> => {
  const iconCandidates = [ALERT_ICON_PATH, "icons/nyx-alert-128.png"];
  let iconUrl: string | null = null;

  for (const path of iconCandidates) {
    try {
      const candidateUrl = chrome.runtime.getURL(path);
      const response = await fetch(candidateUrl);
      if (response.ok) {
        iconUrl = candidateUrl;
        break;
      }
    } catch {
      // Try next icon candidate.
    }
  }

  if (!iconUrl) {
    console.warn("Nyx Guard notification error: icon not available");
    return false;
  }

  return new Promise((resolve) => {
    chrome.notifications.create(
      {
        type: "basic",
        iconUrl,
        title,
        message
      },
      () => {
        if (chrome.runtime.lastError) {
          console.warn("Nyx Guard notification error:", chrome.runtime.lastError.message);
          resolve(false);
          return;
        }
        resolve(true);
      }
    );
  });
};

const maybeNotifyDanger = async (
  tabId: number,
  result: DetectionResult,
  settings: Awaited<ReturnType<typeof getSettings>>
) => {
  if (!settings.enableDangerAlerts) {
    return;
  }

  const highStart = settings.mediumMax + 1;
  const nearHighThreshold = Math.max(0, highStart - 5);
  if (result.score < nearHighThreshold) {
    return;
  }

  const state = alertState.get(tabId);
  const now = Date.now();
  if (
    state &&
    state.domain === result.domain &&
    now - state.lastAlertTs < ALERT_COOLDOWN_MS
  ) {
    return;
  }

  const severity = result.level === "high" ? "ALTO" : "ELEVADO";
  const notified = await createDangerNotification(
    `Nyx Guard: Riesgo ${severity}`,
    `${result.domain} tiene score ${result.score}/100. Evita introducir datos sensibles.`
  );
  if (notified) {
    alertState.set(tabId, { domain: result.domain, lastAlertTs: now });
  }
};

const buildFeatures = async (
  payload: ContentFeatures,
  tabId: number,
  settingsInput?: Awaited<ReturnType<typeof getSettings>>
): Promise<Features> => {
  const settings = settingsInput ?? (await getSettings());
  const domain =
    normalizeDomain(payload.domain ?? "") ??
    normalizeDomain(payload.url) ??
    new URL(payload.url).hostname.toLowerCase();
  const countTrackers = trackerState.get(tabId)?.count ?? 0;
  let virusTotalStatus: Features["virusTotalStatus"] = "no_data";
  let virusTotal: Features["virusTotal"];

  if (settings.enableVirusTotal && settings.virusTotalApiKey) {
    const lookup = await getDomainSummary(domain, settings.virusTotalApiKey);
    virusTotalStatus = lookup.status;
    virusTotal = lookup.summary;
  }

  return {
    ...payload,
    url: payload.url,
    domain,
    countTrackers,
    virusTotalStatus,
    virusTotal: virusTotal ?? undefined
  };
};

const scheduleRecalc = (tabId: number) => {
  if (recalcTimers.has(tabId)) {
    return;
  }

  const timer = setTimeout(() => {
    recalcTimers.delete(tabId);
    void (async () => {
      const payload = lastContentFeatures.get(tabId);
      if (!payload || !isHttpUrl(payload.url)) {
        return;
      }

      const settings = await getSettings();
      const features = await buildFeatures(payload, tabId, settings);

      const result = evaluate(features, settings);
      await saveResult(tabId, result);
      await maybeNotifyDanger(tabId, result, settings);
    })();
  }, 400);

  recalcTimers.set(tabId, timer as unknown as number);
};

chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  const details = info as chrome.declarativeNetRequest.MatchedRuleInfoDebug & {
    tabId?: number;
  };
  const tabId = details.tabId ?? details.request.tabId;

  if (tabId < 0) {
    return;
  }

  const current = trackerState.get(tabId) ?? { count: 0 };
  trackerState.set(tabId, { ...current, count: current.count + 1 });
  scheduleRecalc(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) {
    resetTrackerState(tabId, changeInfo.url);
    void clearResult(tabId);
  }

  if (changeInfo.status === "loading") {
    resetTrackerState(tabId, changeInfo.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  trackerState.delete(tabId);
  alertState.delete(tabId);
  void clearResult(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "nyxguard:features") {
    const payload = message.payload as ContentFeatures;
    const tabId = sender.tab?.id;

    if (!tabId) {
      sendResponse({ ok: false });
      return false;
    }

    void (async () => {
      if (!isHttpUrl(payload.url)) {
        sendResponse({ ok: false });
        return;
      }

      const settings = await getSettings();
      lastContentFeatures.set(tabId, payload);
      const features = await buildFeatures(payload, tabId, settings);

      const result = evaluate(features, settings);
      await saveResult(tabId, result);
      await maybeNotifyDanger(tabId, result, settings);
      sendResponse({ ok: true, result });
    })();

    return true;
  }

  if (message?.type === "nyxguard:getResult") {
    const tabId = message.tabId as number | undefined;
    if (!tabId) {
      sendResponse({ ok: false });
      return false;
    }

    void (async () => {
      const result = await loadResult(tabId);
      sendResponse({ ok: true, result });
    })();

    return true;
  }

  if (message?.type === "nyxguard:updateList") {
    const list = message.list as "allow" | "deny" | undefined;
    const domain = normalizeDomain(message.domain ?? "");

    if (!list || !domain) {
      sendResponse({ ok: false, error: "Invalid domain" });
      return false;
    }

    void (async () => {
      const settings = await getSettings();
      const allowlist = new Set(settings.allowlist);
      const denylist = new Set(settings.denylist);

      if (list === "allow") {
        allowlist.add(domain);
        denylist.delete(domain);
      } else {
        denylist.add(domain);
        allowlist.delete(domain);
      }

      const updated = await updateDomainLists({
        allowlist: Array.from(allowlist),
        denylist: Array.from(denylist)
      });

      sendResponse({ ok: true, settings: updated });
    })();

    return true;
  }

  return false;
});
