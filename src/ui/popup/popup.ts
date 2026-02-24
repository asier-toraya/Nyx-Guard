import { isHttpUrl, normalizeDomain, truncateMiddle } from "../../utils/domains";
import type { DetectionResult, Reason, VirusTotalStatus } from "../../scoring/types";

const siteDomain = document.getElementById("siteDomain") as HTMLDivElement;
const siteUrl = document.getElementById("siteUrl") as HTMLDivElement;
const scoreValue = document.getElementById("scoreValue") as HTMLDivElement;
const scoreLevel = document.getElementById("scoreLevel") as HTMLDivElement;
const status = document.getElementById("status") as HTMLDivElement;
const vtStatus = document.getElementById("vtStatus") as HTMLDivElement;
const reasonsList = document.getElementById("reasonsList") as HTMLUListElement;
const trustBtn = document.getElementById("trustBtn") as HTMLButtonElement;
const blockBtn = document.getElementById("blockBtn") as HTMLButtonElement;
const settingsBtn = document.getElementById("settingsBtn") as HTMLButtonElement;

const setLevelClass = (level: string) => {
  scoreLevel.classList.remove("low", "medium", "high");
  if (level) {
    scoreLevel.classList.add(level);
  }
};

const renderReasons = (reasons: Reason[]) => {
  reasonsList.innerHTML = "";

  if (reasons.length === 0) {
    const empty = document.createElement("li");
    empty.className = "reason";
    empty.innerHTML = `
      <div class="reason-title">No strong signals</div>
      <div class="reason-detail">Nyx Guard did not detect notable issues.</div>
    `;
    reasonsList.appendChild(empty);
    return;
  }

  for (const reason of reasons) {
    const item = document.createElement("li");
    item.className = "reason";
    item.innerHTML = `
      <div class="reason-title">${reason.title}</div>
      <div class="reason-detail">${reason.detail}</div>
      <div class="reason-weight">Weight: ${reason.weight >= 0 ? "+" : ""}${reason.weight}</div>
    `;
    reasonsList.appendChild(item);
  }
};

const renderVirusTotalStatus = (value: VirusTotalStatus | undefined) => {
  const next = value ?? "no_data";
  vtStatus.classList.remove("checked", "no_data", "error");
  vtStatus.classList.add(next);
  if (next === "checked") {
    vtStatus.textContent = "VT: checked";
    return;
  }
  if (next === "error") {
    vtStatus.textContent = "VT: error";
    return;
  }
  vtStatus.textContent = "VT: no data";
};

const renderResult = (result: DetectionResult) => {
  scoreValue.textContent = result.score.toString();
  scoreLevel.textContent = result.level.toUpperCase();
  setLevelClass(result.level);
  status.textContent = `Last scan: ${new Date(result.ts).toLocaleTimeString()}`;
  renderVirusTotalStatus(result.features.virusTotalStatus);
  renderReasons(result.reasons);
};

const renderUnsupported = () => {
  scoreValue.textContent = "-";
  scoreLevel.textContent = "Not supported";
  setLevelClass("");
  status.textContent = "This page scheme is not supported.";
  renderVirusTotalStatus("no_data");
  reasonsList.innerHTML = "";
  trustBtn.disabled = true;
  blockBtn.disabled = true;
};

const renderLoading = () => {
  status.textContent = "Collecting signals...";
  renderVirusTotalStatus("no_data");
};

const updateList = async (list: "allow" | "deny", domain: string) => {
  await chrome.runtime.sendMessage({ type: "nyxguard:updateList", list, domain });
};

const loadActiveTab = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) {
    renderUnsupported();
    return null;
  }

  if (!isHttpUrl(tab.url)) {
    siteDomain.textContent = "Unsupported page";
    siteUrl.textContent = tab.url;
    renderUnsupported();
    return null;
  }

  const domain = normalizeDomain(tab.url) ?? new URL(tab.url).hostname;
  siteDomain.textContent = domain;
  siteUrl.textContent = truncateMiddle(tab.url, 64);

  return { id: tab.id, domain };
};

const fetchResult = async (tabId: number) => {
  const response = await chrome.runtime.sendMessage({ type: "nyxguard:getResult", tabId });
  return response?.result as DetectionResult | null;
};

const triggerRescan = async (tabId: number) => {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "nyxguard:scanNow" });
  } catch {
    // Ignore unsupported pages or unavailable content script.
  }
};

const init = async () => {
  const tab = await loadActiveTab();
  if (!tab) {
    return;
  }

  renderLoading();
  await triggerRescan(tab.id);

  let result = await fetchResult(tab.id);
  if (!result) {
    window.setTimeout(async () => {
      const retry = await fetchResult(tab.id);
      if (retry) {
        renderResult(retry);
      } else {
        status.textContent = "No data yet. Refresh the page.";
      }
    }, 1200);
  } else {
    renderResult(result);
  }

  trustBtn.onclick = async () => {
    await updateList("allow", tab.domain);
    status.textContent = "Added to allowlist.";
  };

  blockBtn.onclick = async () => {
    await updateList("deny", tab.domain);
    status.textContent = "Added to denylist.";
  };
};

settingsBtn.onclick = () => {
  chrome.runtime.openOptionsPage();
};

void init();
