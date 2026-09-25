import { Activity, AlertTriangle, CheckCircle2, Clock3, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { fetchAuditLogs, type AuditLogItem } from "../../lib/admin";
import { formatApiDateTime } from "../../lib/datetime";
import { Panel } from "../ui/Panel";

function auditStatusClass(status: string) {
  const normalized = status.toLowerCase();
  if (normalized === "success" || normalized === "ok") return "audit-status audit-status-success";
  if (normalized === "failed" || normalized === "error") return "audit-status audit-status-danger";
  return "audit-status audit-status-neutral";
}

function actionLabel(action: string) {
  return action.replaceAll("_", " ");
}

function statusLabel(status: string) {
  if (status === "success" || status === "ok") return "Berhasil";
  if (status === "failed" || status === "error") return "Gagal";
  return status;
}

function detailsPreview(details: string) {
  if (!details || details === "{}") return "-";
  try {
    const parsed = JSON.parse(details) as Record<string, unknown>;
    return Object.entries(parsed)
      .slice(0, 4)
      .map(([key, value]) => `${key}: ${String(value)}`)
      .join(" · ");
  } catch {
    return details;
  }
}

export function AdminAuditView() {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      setLogs(await fetchAuditLogs());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal memuat audit log.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const filteredLogs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return logs.filter((item) => {
      const matchesStatus = status === "All" || item.status === status;
      const haystack = [
        item.actor_username,
        item.action,
        item.target_type,
        item.target_id,
        item.ip_address,
        item.details,
        item.status,
      ].join(" ").toLowerCase();
      return matchesStatus && (!needle || haystack.includes(needle));
    });
  }, [logs, query, status]);

  const stats = useMemo(() => {
    const failed = logs.filter((item) => ["failed", "error"].includes(item.status.toLowerCase())).length;
    const actors = new Set(logs.map((item) => item.actor_username).filter(Boolean)).size;
    return { total: logs.length, failed, actors };
  }, [logs]);

  return (
    <section className="admin-audit-page">
      <div className="admin-system-overview">
        <article className="source-health-stat ok">
          <span>Total aktivitas</span>
          <strong>{stats.total}</strong>
        </article>
        <article className={stats.failed ? "source-health-stat degraded" : "source-health-stat ok"}>
          <span>Aktivitas gagal</span>
          <strong>{stats.failed}</strong>
        </article>
        <article className="source-health-stat">
          <span>Aktor unik</span>
          <strong>{stats.actors}</strong>
        </article>
      </div>

      <div className="admin-toolbar">
        <label className="search-field">
          <Search size={15} />
          <input aria-label="Cari log audit" autoComplete="off" onChange={(event) => setQuery(event.target.value)} placeholder="Cari aksi, pengguna, target, atau IP…" type="search" value={query} />
        </label>
        <select aria-label="Filter status audit" onChange={(event) => setStatus(event.target.value)} value={status}>
          <option value="All">Semua status</option>
          <option value="success">Berhasil</option>
          <option value="failed">Gagal</option>
        </select>
        <span className="result-count">{filteredLogs.length} event</span>
      </div>

      <Panel
        className="admin-audit-panel"
        title="Log audit"
        icon={<ShieldAlert size={18} />}
        action={<button className="button-secondary refresh-button" disabled={loading} onClick={() => void load()} type="button"><RefreshCw className={loading ? "loading-spinner" : ""} size={15} />Muat ulang</button>}
      >
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="table-scroll admin-audit-scroll">
          <table>
            <thead>
              <tr>
                <th>Waktu</th>
                <th>Pengguna</th>
                <th>Aksi</th>
                <th>Target</th>
                <th>Status</th>
                <th>IP</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((item) => (
                <tr key={item.id}>
                  <td>
                    <span className="audit-time"><Clock3 size={13} />{formatApiDateTime(item.created_at, { dateStyle: "medium", timeStyle: "short" })}</span>
                  </td>
                  <td>{item.actor_username || "system"}</td>
                  <td><span className="audit-action"><Activity size={13} />{actionLabel(item.action)}</span></td>
                  <td>
                    <div className="source-name-cell">
                      <strong>{item.target_type || "-"}</strong>
                      <span>{item.target_id || "-"}</span>
                    </div>
                  </td>
                  <td>
                    <span className={auditStatusClass(item.status)}>
                      {["failed", "error"].includes(item.status.toLowerCase()) ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
                      {statusLabel(item.status.toLowerCase())}
                    </span>
                  </td>
                  <td>{item.ip_address || "-"}</td>
                  <td className="source-message-cell">{detailsPreview(item.details)}</td>
                </tr>
              ))}
              {loading && filteredLogs.length === 0 && <tr><td className="table-state" colSpan={7}>Memuat audit log…</td></tr>}
              {!loading && filteredLogs.length === 0 && <tr><td className="table-state" colSpan={7}>Audit log tidak ditemukan.</td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
    </section>
  );
}
