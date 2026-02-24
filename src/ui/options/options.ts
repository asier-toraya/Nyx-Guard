import {
  DEFAULT_SETTINGS,
  getSettings,
  normalizeThresholds,
  parseDomainLines,
  saveSettings,
  type Settings
} from "../../storage/settings";

const enableMaliciousChecks = document.getElementById(
  "enableMaliciousChecks"
) as HTMLInputElement;
const enableAdsChecks = document.getElementById("enableAdsChecks") as HTMLInputElement;
const enableContentChecks = document.getElementById(
  "enableContentChecks"
) as HTMLInputElement;
const enableTextSample = document.getElementById("enableTextSample") as HTMLInputElement;
const enableVirusTotal = document.getElementById("enableVirusTotal") as HTMLInputElement;
const enableDangerAlerts = document.getElementById("enableDangerAlerts") as HTMLInputElement;
const sensitivity = document.getElementById("sensitivity") as HTMLInputElement;
const sensitivityValue = document.getElementById("sensitivityValue") as HTMLSpanElement;
const lowMax = document.getElementById("lowMax") as HTMLInputElement;
const mediumMax = document.getElementById("mediumMax") as HTMLInputElement;
const thresholdsHint = document.getElementById("thresholdsHint") as HTMLDivElement;
const virusTotalApiKey = document.getElementById("virusTotalApiKey") as HTMLInputElement;
const allowlist = document.getElementById("allowlist") as HTMLTextAreaElement;
const denylist = document.getElementById("denylist") as HTMLTextAreaElement;
const allowlistHint = document.getElementById("allowlistHint") as HTMLDivElement;
const denylistHint = document.getElementById("denylistHint") as HTMLDivElement;
const saveBtn = document.getElementById("saveBtn") as HTMLButtonElement;
const resetBtn = document.getElementById("resetBtn") as HTMLButtonElement;
const status = document.getElementById("status") as HTMLDivElement;

const updateSensitivityLabel = (value: string) => {
  const parsed = Number.parseFloat(value);
  sensitivityValue.textContent = `${parsed.toFixed(1)}x`;
};

const applySettings = (settings: Settings) => {
  enableMaliciousChecks.checked = settings.enableMaliciousChecks;
  enableAdsChecks.checked = settings.enableAdsChecks;
  enableContentChecks.checked = settings.enableContentChecks;
  enableTextSample.checked = settings.enableTextSample;
  enableVirusTotal.checked = settings.enableVirusTotal;
  enableDangerAlerts.checked = settings.enableDangerAlerts;
  sensitivity.value = settings.sensitivity.toString();
  updateSensitivityLabel(sensitivity.value);
  lowMax.value = settings.lowMax.toString();
  mediumMax.value = settings.mediumMax.toString();
  thresholdsHint.textContent = `High starts at ${settings.mediumMax + 1}.`;
  virusTotalApiKey.value = settings.virusTotalApiKey;
  allowlist.value = settings.allowlist.join("\n");
  denylist.value = settings.denylist.join("\n");
};

const collectSettings = (): Settings => {
  const allowResult = parseDomainLines(allowlist.value);
  const denyResult = parseDomainLines(denylist.value);
  const allowSet = new Set(allowResult.domains);
  const denyDomains = denyResult.domains.filter((domain) => !allowSet.has(domain));

  allowlistHint.textContent = allowResult.invalid.length
    ? `Ignored ${allowResult.invalid.length} invalid entr${allowResult.invalid.length === 1 ? "y" : "ies"}.`
    : "One domain per line.";

  denylistHint.textContent = denyResult.invalid.length
    ? `Ignored ${denyResult.invalid.length} invalid entr${denyResult.invalid.length === 1 ? "y" : "ies"}.`
    : "One domain per line.";

  const normalizedThresholds = normalizeThresholds({
    lowMax: Number.parseInt(lowMax.value, 10),
    mediumMax: Number.parseInt(mediumMax.value, 10)
  });
  lowMax.value = normalizedThresholds.lowMax.toString();
  mediumMax.value = normalizedThresholds.mediumMax.toString();
  thresholdsHint.textContent = `High starts at ${normalizedThresholds.mediumMax + 1}.`;

  return {
    enableMaliciousChecks: enableMaliciousChecks.checked,
    enableAdsChecks: enableAdsChecks.checked,
    enableContentChecks: enableContentChecks.checked,
    enableTextSample: enableTextSample.checked,
    enableVirusTotal: enableVirusTotal.checked,
    enableDangerAlerts: enableDangerAlerts.checked,
    sensitivity: Number.parseFloat(sensitivity.value),
    lowMax: normalizedThresholds.lowMax,
    mediumMax: normalizedThresholds.mediumMax,
    virusTotalApiKey: virusTotalApiKey.value.trim(),
    allowlist: allowResult.domains,
    denylist: denyDomains
  };
};

const save = async () => {
  const settings = collectSettings();
  await saveSettings(settings);
  status.textContent = "Settings saved.";
  window.setTimeout(() => {
    status.textContent = "";
  }, 2000);
};

const reset = async () => {
  await saveSettings(DEFAULT_SETTINGS);
  applySettings(DEFAULT_SETTINGS);
  status.textContent = "Defaults restored.";
  window.setTimeout(() => {
    status.textContent = "";
  }, 2000);
};

sensitivity.addEventListener("input", (event) => {
  updateSensitivityLabel((event.target as HTMLInputElement).value);
});

const refreshThresholdHint = () => {
  const normalized = normalizeThresholds({
    lowMax: Number.parseInt(lowMax.value, 10),
    mediumMax: Number.parseInt(mediumMax.value, 10)
  });
  thresholdsHint.textContent = `High starts at ${normalized.mediumMax + 1}.`;
};

lowMax.addEventListener("input", refreshThresholdHint);
mediumMax.addEventListener("input", refreshThresholdHint);

saveBtn.addEventListener("click", () => void save());
resetBtn.addEventListener("click", () => void reset());

void (async () => {
  const settings = await getSettings();
  applySettings(settings);
})();
