export type AssetRisk = "Low" | "Medium" | "High" | "Critical";

export type Asset = {
  id: number;
  name: string;
  asset_type: string;
  os_version: string;
  owner: string;
  risk: AssetRisk;
  matching_cve: number;
};

export type AssetInput = Omit<Asset, "id" | "matching_cve">;

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
