export type RelatedAssetRef = {
  id: number;
  name: string;
  risk: string;
  reason: string;
};

export type DetailedIOC = {
  indicator: string;
  type: string;
  threat: string;
  severity: string;
  source: string;
  first_seen: string;
  last_seen: string;
  related_assets: RelatedAssetRef[];
};

export async function fetchIocs(type: string): Promise<DetailedIOC[]> {
  const response = await fetch(`/api/iocs?type=${encodeURIComponent(type)}`, { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error(`Gagal memuat IOC (${response.status}).`);
  }
  return response.json();
}
