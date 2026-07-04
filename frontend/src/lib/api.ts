export type Metric = {
  label: string;
  value: number;
  delta: string;
  tone: "danger" | "warning" | "success" | "info";
};

export type CVEItem = {
  cve_id: string;
  severity: string;
  vendor: string;
  product: string;
  published_at: string;
  kev: boolean;
};

export type IOCItem = {
  indicator: string;
  type: string;
  severity: string;
  source: string;
};

export type NewsItem = {
  title: string;
  source: string;
  published_at: string;
  url: string;
  summary: string;
};

export type TechniqueItem = {
  technique_id: string;
  name: string;
  tactic: string;
  count: number;
};

export type AssetExposureItem = {
  asset: string;
  asset_type: string;
  os_version: string;
  matching_cve: number;
  risk: string;
};

export type DistributionPoint = {
  label: string;
  value: number;
};

export type CVETrendPoint = {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
};

export type DashboardPayload = {
  metrics: Metric[];
  cves: CVEItem[];
  iocs: IOCItem[];
  news: NewsItem[];
  techniques: TechniqueItem[];
  exposures: AssetExposureItem[];
  cve_trend: CVETrendPoint[];
  severity_distribution: DistributionPoint[];
  ioc_distribution: DistributionPoint[];
  asset_risk_distribution: DistributionPoint[];
};

export const fallbackDashboard: DashboardPayload = {
  metrics: [
    { label: "Critical CVE (7 hari)", value: 12, delta: "published in the last 7 days", tone: "danger" },
    { label: "Known exploited", value: 4, delta: "tracked in the CISA KEV catalog", tone: "warning" },
    { label: "New indicators", value: 238, delta: "observed in the last 7 days", tone: "success" },
    { label: "High-risk assets", value: 3, delta: "requires exposure review", tone: "info" }
  ],
  cves: [
    { cve_id: "CVE-2026-5281", severity: "Critical", vendor: "Google", product: "Chrome", published_at: "2026-05-21T00:00:00Z", kev: true },
    { cve_id: "CVE-2026-42897", severity: "High", vendor: "Microsoft", product: "Windows", published_at: "2026-05-20T00:00:00Z", kev: true },
    { cve_id: "CVE-2026-3910", severity: "High", vendor: "Fortinet", product: "FortiOS", published_at: "2026-05-19T00:00:00Z", kev: true },
    { cve_id: "CVE-2026-1234", severity: "Medium", vendor: "Cisco", product: "IOS XE", published_at: "2026-05-18T00:00:00Z", kev: false }
  ],
  iocs: [
    { indicator: "185.197.xx.23", type: "ip", severity: "High", source: "AbuseIPDB" },
    { indicator: "176.65.xx.11", type: "ip", severity: "High", source: "OTX" },
    { indicator: "45.77.xx.54", type: "ip", severity: "Medium", source: "AbuseIPDB" },
    { indicator: "103.224.xx.10", type: "domain", severity: "Medium", source: "OTX" },
    { indicator: "192.99.xx.12", type: "hash", severity: "Low", source: "MalwareBazaar" }
  ],
  news: [
    { title: "New Chrome zero-day CVE-2026-5281", source: "THN", published_at: "2026-06-26T08:00:00Z", url: "#fallback-chrome", summary: "Chrome vulnerability observed in active exploitation." },
    { title: "LockBit 3.0 targeting ESXi", source: "BleepingComputer", published_at: "2026-06-25T18:00:00Z", url: "#fallback-lockbit", summary: "Ransomware activity targeting virtualization infrastructure." },
    { title: "Microsoft Patch Tuesday roundup", source: "Microsoft", published_at: "2026-06-25T09:00:00Z", url: "#fallback-patch", summary: "Security updates and vulnerability remediation guidance." }
  ],
  techniques: [
    { technique_id: "T1059", name: "Command and Scripting", tactic: "Execution", count: 45 },
    { technique_id: "T1566", name: "Phishing", tactic: "Initial Access", count: 32 },
    { technique_id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion", count: 28 },
    { technique_id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", count: 18 }
  ],
  exposures: [
    { asset: "FortiGate-01", asset_type: "Firewall", os_version: "7.2.5", matching_cve: 3, risk: "High" },
    { asset: "Win-Server-01", asset_type: "Server", os_version: "2022", matching_cve: 5, risk: "High" },
    { asset: "ESXi-Host-01", asset_type: "Hypervisor", os_version: "7.0U3", matching_cve: 2, risk: "Medium" },
    { asset: "Exchange-01", asset_type: "Mail Server", os_version: "2019", matching_cve: 4, risk: "High" }
  ],
  cve_trend: [
    { date: "2026-06-17", critical: 1, high: 3, medium: 5, low: 2, unknown: 0 },
    { date: "2026-06-18", critical: 0, high: 4, medium: 7, low: 1, unknown: 0 },
    { date: "2026-06-19", critical: 2, high: 6, medium: 8, low: 3, unknown: 1 },
    { date: "2026-06-20", critical: 1, high: 2, medium: 4, low: 2, unknown: 0 },
    { date: "2026-06-21", critical: 3, high: 5, medium: 9, low: 2, unknown: 0 },
    { date: "2026-06-22", critical: 0, high: 3, medium: 6, low: 4, unknown: 1 },
    { date: "2026-06-23", critical: 2, high: 7, medium: 8, low: 2, unknown: 0 },
    { date: "2026-06-24", critical: 1, high: 4, medium: 7, low: 3, unknown: 0 },
    { date: "2026-06-25", critical: 4, high: 8, medium: 12, low: 5, unknown: 1 },
    { date: "2026-06-26", critical: 3, high: 6, medium: 9, low: 2, unknown: 0 },
    { date: "2026-06-27", critical: 1, high: 5, medium: 8, low: 4, unknown: 0 },
    { date: "2026-06-28", critical: 2, high: 4, medium: 6, low: 2, unknown: 1 },
    { date: "2026-06-29", critical: 1, high: 7, medium: 10, low: 3, unknown: 0 },
    { date: "2026-06-30", critical: 3, high: 9, medium: 11, low: 4, unknown: 0 }
  ],
  severity_distribution: [
    { label: "Critical", value: 54 },
    { label: "High", value: 312 },
    { label: "Medium", value: 690 },
    { label: "Low", value: 188 },
    { label: "Unknown", value: 21 }
  ],
  ioc_distribution: [
    { label: "IP", value: 142 },
    { label: "DOMAIN", value: 88 },
    { label: "URL", value: 61 },
    { label: "HASH", value: 109 }
  ],
  asset_risk_distribution: [
    { label: "High", value: 3 },
    { label: "Medium", value: 1 },
    { label: "Low", value: 0 }
  ]
};

export async function fetchDashboard(): Promise<DashboardPayload> {
  const response = await fetch("/api/dashboard");
  if (!response.ok) {
    throw new Error(`Dashboard API failed: ${response.status}`);
  }
  return response.json();
}
