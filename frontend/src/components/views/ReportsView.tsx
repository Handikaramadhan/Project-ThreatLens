import { Download, FileJson, FileSpreadsheet } from "lucide-react";
import type { DashboardPayload } from "../../lib/api";

export function ReportsView({ data }: { data: DashboardPayload }) {
  function download(format: "json" | "csv") {
    const json = JSON.stringify(data, null, 2);
    const csvRows = [
      ["CVE ID", "Severity", "Vendor", "Published", "KEV"],
      ...data.cves.map((item) => [item.cve_id, item.severity, item.vendor, item.published_at, item.kev ? "Yes" : "No"])
    ];
    const csv = csvRows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n");
    const blob = new Blob([format === "json" ? json : csv], { type: format === "json" ? "application/json" : "text/csv" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `threatlens-report.${format}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="report-grid">
      <article className="report-option">
        <FileJson size={24} />
        <div><strong>Data intelijen JSON</strong><span>Ringkasan, CVE, IOC, feed, dan paparan aset.</span></div>
        <button aria-label="Unduh laporan JSON" onClick={() => download("json")} title="Unduh JSON" type="button"><Download size={18} /></button>
      </article>
      <article className="report-option">
        <FileSpreadsheet size={24} />
        <div><strong>Laporan CVE CSV</strong><span>Daftar CVE terbaru untuk analisis lanjutan.</span></div>
        <button aria-label="Unduh laporan CSV" onClick={() => download("csv")} title="Unduh CSV" type="button"><Download size={18} /></button>
      </article>
    </section>
  );
}
