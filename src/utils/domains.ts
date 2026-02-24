export function normalizeDomain(input: string): string | null {
  const raw = input.trim().toLowerCase();
  if (!raw) {
    return null;
  }

  try {
    let hostname = raw;
    if (raw.includes("://")) {
      hostname = new URL(raw).hostname;
    } else if (raw.includes("/")) {
      hostname = new URL(`http://${raw}`).hostname;
    }

    hostname = hostname.trim().toLowerCase();
    hostname = hostname.replace(/^www\./, "");

    if (!hostname || hostname.includes(" ")) {
      return null;
    }

    return hostname;
  } catch {
    return null;
  }
}

export function isHttpUrl(url: string): boolean {
  return url.startsWith("http://") || url.startsWith("https://");
}

export function isPunycodeDomain(domain: string): boolean {
  return domain.split(".").some((label) => label.startsWith("xn--"));
}

export function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value;
  }

  const head = Math.floor((maxLength - 3) / 2);
  const tail = Math.ceil((maxLength - 3) / 2);
  return `${value.slice(0, head)}...${value.slice(value.length - tail)}`;
}
