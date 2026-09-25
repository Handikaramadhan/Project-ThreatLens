export type AssetRisk = "Low" | "Medium" | "High" | "Critical";
export type AssetExposureStatus = "open" | "validated" | "false_positive" | "accepted_risk" | "remediated";

export type Asset = {
  id: number;
  name: string;
  asset_type: string;
  os_version: string;
  vendor: string;
  product: string;
  version: string;
  environment: string;
  criticality: AssetRisk;
  internet_exposed: boolean;
  owner: string;
  risk: AssetRisk;
  matching_cve: number;
};

export type AssetInput = Omit<Asset, "id" | "matching_cve">;

export type AssetExposure = {
  cve_id: string;
  title: string;
  severity: string;
  risk: AssetRisk;
  matching_score: number;
  confidence: "High" | "Medium" | "Low";
  match_type: string;
  affected_vendor: string;
  affected_product: string;
  affected_version: string;
  affected_version_range: string;
  status: AssetExposureStatus;
  review_note: string;
  reviewed_at: string | null;
  reviewed_by: string;
  reason: string;
  evidence: string[];
  limitations: string[];
  published_at: string;
  kev: boolean;
};

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    const detail = Array.isArray(body.detail)
      ? body.detail[0]?.msg?.replace("Value error, ", "")
      : body.detail;
    throw new Error(typeof detail === "string" ? detail : "Request failed");
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

export function fetchAssets() {
  return request<Asset[]>("/api/assets");
}

export function createAsset(payload: AssetInput, csrfToken: string) {
  return request<Asset>("/api/assets", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify(payload),
  });
}

export function updateAsset(assetId: number, payload: AssetInput, csrfToken: string) {
  return request<Asset>(`/api/assets/${assetId}`, {
    method: "PUT",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify(payload),
  });
}

export function deleteAsset(assetId: number, csrfToken: string) {
  return request<void>(`/api/assets/${assetId}`, {
    method: "DELETE",
    headers: { "X-CSRF-Token": csrfToken },
  });
}

export function recalculateAssetExposures(csrfToken: string) {
  return request<{ matching_cve: number }>("/api/assets/recalculate", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
  });
}

export function fetchAssetExposures(assetId: number) {
  return request<AssetExposure[]>(`/api/assets/${assetId}/exposures`);
}

export function updateAssetExposure(
  assetId: number,
  cveId: string,
  payload: { status: AssetExposureStatus; review_note: string },
  csrfToken: string,
) {
  return request<AssetExposure>(`/api/assets/${assetId}/exposures/${encodeURIComponent(cveId)}`, {
    method: "PATCH",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify(payload),
  });
}
