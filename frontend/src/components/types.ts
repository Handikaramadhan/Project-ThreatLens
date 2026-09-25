export type ViewKey = "dashboard" | "ai" | "cve" | "feed" | "ioc" | "sources" | "assets" | "alerts" | "reports" | "users" | "audit" | "system";

export const viewMeta: Record<ViewKey, { eyebrow: string; title: string }> = {
  dashboard: { eyebrow: "Workspace / Ringkasan", title: "Ringkasan operasional" },
  ai: { eyebrow: "Intelijen / Analisis AI", title: "Intelijen ancaman AI" },
  cve: { eyebrow: "Intelijen / Kerentanan", title: "Intelijen kerentanan" },
  feed: { eyebrow: "Intelijen / Threat feed", title: "Threat feed" },
  ioc: { eyebrow: "Intelijen / Indikator", title: "Indikator ancaman" },
  sources: { eyebrow: "Operasional / Sumber", title: "Kesehatan sumber" },
  assets: { eyebrow: "Operasional / Inventaris", title: "Aset terpantau" },
  alerts: { eyebrow: "Operasional / Deteksi", title: "Peringatan" },
  reports: { eyebrow: "Operasional / Ekspor", title: "Laporan" },
  users: { eyebrow: "Sistem / Akses", title: "Pengguna" },
  audit: { eyebrow: "Sistem / Audit", title: "Log audit" },
  system: { eyebrow: "Sistem / Kesehatan", title: "Kesehatan sistem" }
};

export function currentView(): ViewKey {
  const candidate = window.location.hash.replace(/^#\/?/, "").split("?")[0] as ViewKey;
  return candidate in viewMeta ? candidate : "dashboard";
}
