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

export type SourceStatusItem = {
  id: string;
  name: string;
  category: string;
  status: "ok" | "fallback" | "skipped" | "error" | "unknown" | string;
  count: number | null;
  message: string;
  consecutive_failures: number;
  last_success_at: string | null;
  last_seen_at: string | null;
};

export type CollectionSummary = {
  status: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  degraded_sources: number;
  sources: SourceStatusItem[];
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
  collection: CollectionSummary | null;
};

export const emptyDashboard: DashboardPayload = {
  metrics: [
    { label: "Critical CVE (7 hari)", value: 0, delta: "data belum tersedia", tone: "danger" },
    { label: "Known exploited", value: 0, delta: "data belum tersedia", tone: "warning" },
    { label: "New indicators", value: 0, delta: "data belum tersedia", tone: "success" },
    { label: "High-risk assets", value: 0, delta: "data belum tersedia", tone: "info" }
  ],
  cves: [],
  iocs: [],
  news: [],
  techniques: [],
  exposures: [],
  cve_trend: [],
  severity_distribution: [],
  ioc_distribution: [],
  asset_risk_distribution: [],
  collection: null
};

export async function fetchDashboard(): Promise<DashboardPayload> {
  const response = await fetch("/api/dashboard");
  if (!response.ok) {
    throw new Error(`Dashboard API failed: ${response.status}`);
  }
  return response.json();
}
