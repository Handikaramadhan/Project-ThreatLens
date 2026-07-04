export type CVSSMetrics = {
  version: string;
  vector: string;
  base_score: number;
  base_severity: string;
  exploitability_score: number | null;
  impact_score: number | null;
  attack_vector: string;
  attack_complexity: string;
  privileges_required: string;
  user_interaction: string;
  scope: string;
  confidentiality_impact: string;
  integrity_impact: string;
  availability_impact: string;
};

export type AffectedProduct = {
  vendor: string;
  product: string;
  version: string;
  vulnerable: boolean;
  version_range: string;
};

export type CVEReference = {
  url: string;
  source: string;
  tags: string[];
};

export type RemediationItem = {
  text: string;
  source: string;
  url: string;
};

export type CVEDetail = {
  cve_id: string;
  title: string;
  description: string;
  severity: string;
  vendor: string;
  product: string;
  cvss_score: number;
  cvss: CVSSMetrics | null;
  kev: boolean;
  exploit_status: {
    known_exploited: boolean;
    date_added: string;
    action_due: string;
    required_action: string;
    ransomware_use: string;
    notes: string;
  };
  weaknesses: string[];
  affected_products: AffectedProduct[];
  mitigation: RemediationItem[];
  workarounds: RemediationItem[];
  remediation_sources: CVEReference[];
  references: CVEReference[];
  related_iocs: Array<{
    indicator: string;
    type: string;
    threat: string;
    severity: string;
    source: string;
  }>;
  related_assets: Array<{
    id: number;
    name: string;
    asset_type: string;
    os_version: string;
    owner: string;
    risk: string;
  }>;
  related_news: Array<{
    title: string;
    source: string;
    url: string;
    published_at: string;
  }>;
  published_at: string;
  source: string;
  detail_source: string;
  fetched_at: string | null;
  root_cause: {
    category: string;
    summary: string;
    weaknesses: string[];
    basis: string;
    confidence: string;
  };
  mitre_techniques: Array<{
    technique_id: string;
    name: string;
    tactic: string;
    rationale: string;
    confidence: string;
    url: string;
  }>;
};

export type CVEListItem = {
  cve_id: string;
  severity: string;
  vendor: string;
  product: string;
  published_at: string;
  kev: boolean;
};

export type CVEPage = {
  items: CVEListItem[];
  total: number;
  page: number;
  limit: number;
  pages: number;
};

export async function fetchCves(
  query: string,
  severity: string,
  page: number,
  limit = 500,
): Promise<CVEPage> {
  const params = new URLSearchParams({
    query,
    severity,
    page: String(page),
    limit: String(limit),
  });
  const response = await fetch(`/api/cves?${params}`, { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error(`Gagal memuat CVE (${response.status}).`);
  }
  return response.json();
}

export async function fetchCveDetail(cveId: string): Promise<CVEDetail> {
  const response = await fetch(`/api/cves/${encodeURIComponent(cveId)}`, {
    credentials: "same-origin",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Gagal memuat detail CVE." }));
    throw new Error(typeof body.detail === "string" ? body.detail : "Gagal memuat detail CVE.");
  }
  return response.json();
}
