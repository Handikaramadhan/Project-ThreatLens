export type ViewKey = "dashboard" | "ai" | "cve" | "feed" | "ioc" | "assets" | "alerts" | "reports" | "users";

export const viewMeta: Record<ViewKey, { eyebrow: string; title: string }> = {
  dashboard: { eyebrow: "Workspace / Overview", title: "Operational overview" },
  ai: { eyebrow: "Intelligence / AI Analyst", title: "AI threat intelligence" },
  cve: { eyebrow: "Intelligence / Vulnerabilities", title: "Vulnerability intelligence" },
  feed: { eyebrow: "Intelligence / Sources", title: "Threat feed" },
  ioc: { eyebrow: "Intelligence / Indicators", title: "Indicator intelligence" },
  assets: { eyebrow: "Operations / Inventory", title: "Monitored assets" },
  alerts: { eyebrow: "Operations / Detection", title: "Alerts" },
  reports: { eyebrow: "Operations / Export", title: "Reports" },
  users: { eyebrow: "System / Access", title: "User management" }
};

export function currentView(): ViewKey {
  const candidate = window.location.hash.replace(/^#\/?/, "") as ViewKey;
  return candidate in viewMeta ? candidate : "dashboard";
}
