import { Activity, AlertTriangle, CheckCircle2, Clock3, Database, GitBranch, HardDrive, RefreshCw, Server, Wifi } from "lucide-react";
import { useEffect, useState } from "react";
import { fetchSystemHealth, type SystemHealth } from "../../lib/admin";
import { formatApiDateTime } from "../../lib/datetime";
import { Panel } from "../ui/Panel";

function healthTone(status: string) {
  const normalized = status.toLowerCase();
  if (normalized === "ok" || normalized === "healthy") return "ok";
  if (normalized === "unknown" || normalized === "never_run") return "warning";
  return "degraded";
}

function HealthCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  const tone = healthTone(value);
  return (
    <article className={`system-health-card system-health-card-${tone}`}>
      <div>{icon}<span>{label}</span></div>
      <strong>{value || "-"}</strong>
    </article>
  );
}

function formatOptionalDate(value: string | null) {
  return value ? formatApiDateTime(value, { dateStyle: "medium", timeStyle: "short" }) : "-";
}

export function AdminSystemHealthView() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      setHealth(await fetchSystemHealth());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal memuat system health.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section className="admin-system-page">
      <div className="admin-system-hero">
        <div>
          <span>Status layanan</span>
          <h2>Kondisi layanan ThreatLens</h2>
        </div>
        <button className="button-secondary refresh-button" disabled={loading} onClick={() => void load()} type="button">
          <RefreshCw className={loading ? "loading-spinner" : ""} size={15} />
          Muat ulang
        </button>
      </div>

      {error && <div className="form-error" role="alert">{error}</div>}

      {health ? (
        <>
          <div className="system-health-grid">
            <HealthCard icon={<Server size={18} />} label="API service" value={health.service} />
            <HealthCard icon={<Database size={18} />} label="Database" value={health.database} />
            <HealthCard icon={<Wifi size={18} />} label="Redis" value={health.redis} />
            <HealthCard icon={<Activity size={18} />} label="Collector" value={health.latest_collection_status} />
          </div>

          <Panel className="system-health-detail-panel" title="Detail sistem" icon={<HardDrive size={18} />}>
            <div className="system-health-detail-grid">
              <div>
                <span><GitBranch size={14} />Alembic revision</span>
                <strong>{health.alembic_revision || "unknown"}</strong>
              </div>
              <div>
                <span><Clock3 size={14} />Collector dimulai</span>
                <strong>{formatOptionalDate(health.latest_collection_started_at)}</strong>
              </div>
              <div>
                <span><Clock3 size={14} />Collector selesai</span>
                <strong>{formatOptionalDate(health.latest_collection_finished_at)}</strong>
              </div>
              <div>
                <span><CheckCircle2 size={14} />Aktivitas audit</span>
                <strong>{health.audit_events}</strong>
              </div>
              <div className={health.failed_alert_deliveries > 0 ? "system-health-danger" : ""}>
                <span><AlertTriangle size={14} />Peringatan gagal dikirim</span>
                <strong>{health.failed_alert_deliveries}</strong>
              </div>
            </div>
          </Panel>
        </>
      ) : (
        <div className="alert-loading" role="status"><RefreshCw className="loading-spinner" size={16} /> Memuat status sistem…</div>
      )}
    </section>
  );
}
