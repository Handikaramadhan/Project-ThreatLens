import type { CVEItem } from "../../lib/api";

export function severityClass(severity: string) {
  return `severity severity-${severity.toLowerCase()}`;
}

type Props = {
  cves: CVEItem[];
  onSelect?: (cveId: string) => void;
  selectedId?: string;
};

export function CveTable({ cves, onSelect, selectedId }: Props) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr><th>CVE ID</th><th>Severity</th><th>Vendor</th><th>Product</th><th>Published</th><th>KEV</th></tr>
        </thead>
        <tbody>
          {cves.map((item) => (
            <tr
              className={onSelect ? `clickable-row${selectedId === item.cve_id ? " selected" : ""}` : undefined}
              key={item.cve_id}
              onClick={onSelect ? () => onSelect(item.cve_id) : undefined}
              onKeyDown={onSelect ? (event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(item.cve_id);
                }
              } : undefined}
              tabIndex={onSelect ? 0 : undefined}
            >
              <td>{item.cve_id}</td>
              <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
              <td>{item.vendor}</td>
              <td>{item.product || "Unknown"}</td>
              <td>{new Date(item.published_at).toLocaleDateString("id-ID")}</td>
              <td>{item.kev ? "Yes" : "No"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
