import { Database, Download, RefreshCw, Server } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { IOCItem } from "../../lib/api";
import { fetchIocs, type DetailedIOC } from "../../lib/iocs";
import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";
import { severityClass } from "../ui/CveTable";

export function IocView({ iocs }: { iocs: IOCItem[] }) {
  const [iocType, setIocType] = useState("domain");
  const [detailed, setDetailed] = useState<DetailedIOC[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadedType, setLoadedType] = useState("");
  const [error, setError] = useState("");
  const requestId = useRef(0);
  const fallbackItems = useMemo(() => iocs.filter((item) => item.type.toLowerCase() === iocType), [iocs, iocType]);
  const items = loadedType === iocType ? detailed : fallbackItems.map((item) => ({ ...item, threat: "", first_seen: "", last_seen: "", related_assets: [] }));

  async function load(type = iocType) {
    const currentRequest = ++requestId.current;
    setLoading(true);
    setError("");
    setLoadedType("");
    try {
      const response = await fetchIocs(type);
      if (currentRequest !== requestId.current) return;
      setDetailed(response);
      setLoadedType(type);
    } catch (reason) {
      if (currentRequest !== requestId.current) return;
      setError(reason instanceof Error ? reason.message : "Gagal memuat IOC.");
      setDetailed([]);
    } finally {
      if (currentRequest === requestId.current) setLoading(false);
    }
  }

  useEffect(() => {
    void load(iocType);
    return () => { requestId.current += 1; };
  }, [iocType]);

  return (
    <section className="view-grid">
      <Panel
        title="IOC Feed"
        icon={<Database size={18} />}
        wide
        action={(
          <>
          <a
            className="panel-export-action"
            download
            href={`/api/iocs/export.xlsx?type=${encodeURIComponent(iocType)}`}
            title={`Export ${iocType.toUpperCase()} ke Excel`}
          >
            <Download size={15} />
            <span>Export .xlsx</span>
          </a>
          <button className="button-secondary refresh-button" disabled={loading} onClick={() => void load()} type="button">
            <RefreshCw className={loading ? "loading-spinner" : ""} size={15} />
            Muat ulang
          </button>
          </>
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
            <thead><tr><th>Indicator</th><th>Risk</th><th>Source</th><th>Related assets</th></tr></thead>
            <tbody>
              {items.map((item) => (
                <tr key={`${item.type}-${item.indicator}`}>
                  <td>
                    <div className="source-name-cell">
                      <strong>{item.indicator}</strong>
                      <span>{item.threat || item.type.toUpperCase()}</span>
                    </div>
                  </td>
                  <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
                  <td>{item.source}</td>
                  <td>
                    {item.related_assets.length ? (
                      <div className="ioc-related-assets">
                        {item.related_assets.map((asset) => (
                          <span key={asset.id} title={asset.reason}><Server size={12} />{asset.name}</span>
                        ))}
                      </div>
                    ) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        {loading && items.length === 0 && <div className="table-state" role="status">Memuat IOC…</div>}
        {!loading && !error && items.length === 0 && <EmptyState icon={<Database size={22} />} text={`Belum ada IOC ${iocType.toUpperCase()}.`} />}
      </Panel>
    </section>
  );
}
