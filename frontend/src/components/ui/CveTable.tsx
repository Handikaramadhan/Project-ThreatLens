import type { CVEItem } from "../../lib/api";
import { formatApiDate } from "../../lib/datetime";

export function severityClass(severity: string) {
  return `severity severity-${severity.toLowerCase()}`;
}

type Props = {
  cves: CVEItem[];
  selectedId?: string;
};

export function CveTable({ cves, selectedId }: Props) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr><th>CVE ID</th><th>Severity</th><th>Vendor</th><th>Product</th><th>Published</th><th>KEV</th></tr>
        </thead>
        <tbody>
          {cves.map((item) => (
            <tr
              className={`clickable-row${selectedId === item.cve_id ? " selected" : ""}`}
              key={item.cve_id}
            >
              <td><a className="cve-id-link" href={`#/cve?selected=${encodeURIComponent(item.cve_id)}`}>{item.cve_id}</a></td>
              <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
              <td>{item.vendor}</td>
              <td>{item.product || "Unknown"}</td>
              <td>{formatApiDate(item.published_at)}</td>
              <td>{item.kev ? "Yes" : "No"}</td>
            </tr>
          ))}
          {cves.length === 0 && <tr><td className="table-state" colSpan={6}>CVE tidak ditemukan.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
