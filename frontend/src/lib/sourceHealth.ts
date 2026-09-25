import type { SourceStatusItem } from "./api";

export function sourceHealthClass(item: SourceStatusItem) {
  return `source-health source-health-${item.status}`;
}

export function sourceStatusLabel(status: string) {
  const labels: Record<string, string> = {
    ok: "OK",
    fallback: "Fallback",
    skipped: "Skipped",
    error: "Error",
    stale: "Stale",
  };
  return labels[status] ?? status;
}

export function collectionStatusLabel(status: string) {
  const labels: Record<string, string> = {
    success: "Berhasil",
    partial: "Sebagian berhasil",
    running: "Sedang berjalan",
    interrupted: "Terhenti",
    failed: "Gagal",
  };
  return labels[status] ?? status;
}

export function sourceStatusBuckets(sources: SourceStatusItem[]) {
  return sources.reduce(
    (buckets, source) => {
      if (source.status === "ok") buckets.ok += 1;
      else if (source.status === "error" || source.status === "stale") buckets.degraded += 1;
      else buckets.warning += 1;
      return buckets;
    },
    { ok: 0, warning: 0, degraded: 0 },
  );
}

export function formatDuration(seconds: number | null) {
  if (seconds === null) return "Belum diketahui";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  return `${minutes}m ${remainingSeconds}s`;
}
