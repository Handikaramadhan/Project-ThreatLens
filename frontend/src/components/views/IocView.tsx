import { Database, Download } from "lucide-react";
import { useState } from "react";
import type { IOCItem } from "../../lib/api";
import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";
import { severityClass } from "../ui/CveTable";

export function IocView({ iocs }: { iocs: IOCItem[] }) {
  const [iocType, setIocType] = useState("domain");
  const items = iocs.filter((item) => item.type.toLowerCase() === iocType);
  return (
    <section className="view-grid">
      <Panel
        title="IOC Feed"
        icon={<Database size={18} />}
        wide
        action={(
          <a
            className="panel-export-action"
            download
            href={`/api/iocs/export.xlsx?type=${encodeURIComponent(iocType)}`}
            title={`Export ${iocType.toUpperCase()} ke Excel`}
          >
            <Download size={15} />
            <span>Export .xlsx</span>
          </a>
        )}
      >
        <div className="ioc-tabs">
          {["ip", "domain", "url", "hash"].map((type) => (
            <button className={iocType === type ? "active" : ""} key={type} onClick={() => setIocType(type)} type="button">
              {type.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Indicator</th><th>Risk</th><th>Source</th></tr></thead>
            <tbody>
              {items.map((item) => (
                <tr key={`${item.type}-${item.indicator}`}>
                  <td>{item.indicator}</td>
                  <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
                  <td>{item.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {items.length === 0 && <EmptyState icon={<Database size={22} />} text={`Belum ada IOC ${iocType.toUpperCase()}.`} />}
      </Panel>
    </section>
  );
}
