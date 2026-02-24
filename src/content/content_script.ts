import { normalizeDomain } from "../utils/domains";
import type { ContentFeatures } from "../scoring/types";

const LOGIN_KEYWORDS = [
  "login",
  "log in",
  "sign in",
  "verify",
  "bank",
  "wallet",
  "account",
  "iniciar sesion",
  "acceder",
  "verificar",
  "banco",
  "cartera",
  "cuenta"
];
const NOTIFICATION_KEYWORDS = [
  "enable notifications",
  "click allow",
  "tap allow",
  "press allow",
  "allow to continue",
  "enable to continue",
  "habilitar notificaciones",
  "permitir notificaciones",
  "haz clic en permitir",
  "to continue allow",
  "para continuar"
];

const AD_TOKENS = ["ad", "ads", "sponsor", "sponsored", "promoted", "taboola", "outbrain"];

const findKeywords = (text: string, keywords: string[]): string[] => {
  const lower = text.toLowerCase();
  const hits = new Set<string>();
  for (const keyword of keywords) {
    if (lower.includes(keyword)) {
      hits.add(keyword);
    }
  }
  return Array.from(hits);
};

const getVisibleText = (): string => {
  return document.body?.innerText ?? "";
};

const detectOverlays = () => {
  if (!document.body || !document.documentElement) {
    return { overlayCount: 0, hasBlockingOverlay: false };
  }

  const elements = Array.from(document.querySelectorAll("body *"));
  const maxElements = 2000;
  let overlayCount = 0;
  let hasBlockingOverlay = false;

  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;

  for (let i = 0; i < elements.length && i < maxElements; i += 1) {
    const element = elements[i];
    const style = window.getComputedStyle(element);

    if (style.position !== "fixed" && style.position !== "sticky") {
      continue;
    }

    const rect = element.getBoundingClientRect();
    if (rect.width < viewportWidth * 0.8 || rect.height < viewportHeight * 0.8) {
      continue;
    }

    const zIndex = Number.parseInt(style.zIndex || "0", 10);
    if (Number.isNaN(zIndex) || zIndex < 1000) {
      continue;
    }

    overlayCount += 1;

    if (rect.width >= viewportWidth * 0.9 && rect.height >= viewportHeight * 0.9) {
      const bodyOverflow = window.getComputedStyle(document.body).overflow;
      const htmlOverflow = window.getComputedStyle(document.documentElement).overflow;
      const ariaModal = element.getAttribute("aria-modal") === "true";
      const roleDialog = element.getAttribute("role") === "dialog";

      if (bodyOverflow === "hidden" || htmlOverflow === "hidden" || ariaModal || roleDialog) {
        hasBlockingOverlay = true;
      }
    }
  }

  return { overlayCount, hasBlockingOverlay };
};

const countAdLikeElements = () => {
  const matcher = new RegExp(`\\b(${AD_TOKENS.join("|")})\\b`);
  const elements = Array.from(document.querySelectorAll("[id], [class]"));
  let count = 0;

  for (const element of elements) {
    const id = element.id?.toLowerCase() ?? "";
    const className = typeof element.className === "string" ? element.className.toLowerCase() : "";

    if (matcher.test(id) || matcher.test(className)) {
      count += 1;
    }

    if (count >= 200) {
      break;
    }
  }

  return count;
};

const countHiddenIframes = () => {
  const iframes = Array.from(document.querySelectorAll("iframe"));
  let count = 0;

  for (const frame of iframes) {
    const style = window.getComputedStyle(frame);
    const rect = frame.getBoundingClientRect();

    const hiddenByStyle =
      style.display === "none" ||
      style.visibility === "hidden" ||
      Number.parseFloat(style.opacity || "1") === 0;

    const hiddenBySize = rect.width <= 1 || rect.height <= 1;
    const hiddenOffscreen =
      rect.bottom < 0 ||
      rect.right < 0 ||
      rect.left > window.innerWidth + 100 ||
      rect.top > window.innerHeight + 100;

    if (hiddenByStyle || hiddenBySize || hiddenOffscreen) {
      count += 1;
    }
  }

  return count;
};

const collectNotificationKeywords = (text: string): string[] => {
  const hits = new Set<string>(findKeywords(text, NOTIFICATION_KEYWORDS));

  const buttons = Array.from(
    document.querySelectorAll("button, a, input[type=button], input[type=submit]")
  );

  for (const button of buttons) {
    const label =
      (button.textContent ?? "") ||
      (button instanceof HTMLInputElement ? button.value : "");
    const normalized = label.trim().toLowerCase();
    if (!normalized) {
      continue;
    }

    if (normalized.includes("allow")) {
      hits.add("allow");
    }
    if (normalized.includes("enable")) {
      hits.add("enable");
    }
    if (normalized.includes("notifications")) {
      hits.add("notifications");
    }
    if (normalized.includes("continue")) {
      hits.add("continue");
    }
  }

  return Array.from(hits);
};

const shouldCaptureTextSample = async () => {
  const data = await chrome.storage.local.get("settings");
  return data.settings?.enableTextSample === true;
};

const collectFeatures = async (): Promise<ContentFeatures> => {
  const url = window.location.href;
  const domain = normalizeDomain(window.location.hostname) ?? window.location.hostname.toLowerCase();
  const hasPasswordForm = Boolean(document.querySelector("input[type=password]"));

  const bodyText = getVisibleText();
  const suspiciousLoginKeywordsFound = hasPasswordForm
    ? findKeywords(bodyText, LOGIN_KEYWORDS)
    : [];

  const { overlayCount, hasBlockingOverlay } = detectOverlays();
  const notificationDarkPatternKeywords = collectNotificationKeywords(bodyText);
  const adLikeElementsCount = countAdLikeElements();
  const iframeHiddenCount = countHiddenIframes();

  let pageTextSample: string | undefined;
  if (await shouldCaptureTextSample()) {
    pageTextSample = bodyText.replace(/\s+/g, " ").trim().slice(0, 2000);
  }

  return {
    url,
    domain,
    hasPasswordForm,
    suspiciousLoginKeywordsFound,
    overlayCount,
    hasBlockingOverlay,
    notificationDarkPatternKeywords,
    adLikeElementsCount,
    iframeHiddenCount,
    pageTextSample
  };
};

const sendFeatures = async () => {
  const payload = await collectFeatures();
  chrome.runtime.sendMessage({ type: "nyxguard:features", payload });
};

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "nyxguard:scanNow") {
    return false;
  }

  void sendFeatures()
    .then(() => sendResponse({ ok: true }))
    .catch(() => sendResponse({ ok: false }));
  return true;
});

if (window.top === window) {
  if (document.readyState === "loading") {
    window.addEventListener("DOMContentLoaded", () => {
      void sendFeatures();
      window.setTimeout(() => void sendFeatures(), 2000);
    });
  } else {
    void sendFeatures();
    window.setTimeout(() => void sendFeatures(), 2000);
  }
}
