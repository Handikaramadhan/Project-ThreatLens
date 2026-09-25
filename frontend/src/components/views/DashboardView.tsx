import {
  BarChart3,
  Crosshair,
  Database,
  Globe2,
  PieChart,
  RadioTower,
  Server,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import type { DashboardPayload, DistributionPoint, Metric } from "../../lib/api";
import { formatApiDateTime } from "../../lib/datetime";
import { collectionStatusLabel, formatDuration, sourceStatusBuckets } from "../../lib/sourceHealth";
import { CveTable } from "../ui/CveTable";
import { NewsList } from "../ui/NewsList";
import { Panel } from "../ui/Panel";

function metricClass(metric: Metric) {
  return `metric metric-${metric.tone}`;
}

const metricIcons = [ShieldAlert, Crosshair, Database, Server];
const severityOrder = ["Critical", "High", "Medium", "Low", "Unknown"];
const iocColors = ["#ef3340", "#45b8c8", "#d9a441", "#4fbf79", "#686c76"];
const metricLabels: Record<string, string> = {
  "Critical CVE (7 hari)": "CVE kritis (7 hari)",
  "Known exploited": "Eksploitasi diketahui",
  "New indicators": "Indikator baru",
  "High-risk assets": "Aset berisiko tinggi",
};
const metricDescriptions: Record<string, string> = {
  "published in the last 7 days": "diterbitkan dalam 7 hari",
  "tracked in the CISA KEV catalog": "tercatat di katalog CISA KEV",
  "observed in the last 7 days": "terpantau dalam 7 hari",
  "requires exposure review": "perlu tinjauan paparan",
};

function sortedDistribution(items: DistributionPoint[]) {
  return [...items].sort(
    (left, right) => severityOrder.indexOf(left.label) - severityOrder.indexOf(right.label),
  );
}

function conicGradient(items: DistributionPoint[]) {
  const total = items.reduce((sum, item) => sum + item.value, 0);
  if (!total) return "var(--tl-line)";
  let cursor = 0;
  const stops = items.map((item, index) => {
    const start = cursor;
    cursor += (item.value / total) * 100;
    return `${iocColors[index % iocColors.length]} ${start}% ${cursor}%`;
  });
  return `conic-gradient(${stops.join(", ")})`;
}

export function DashboardView({ data }: { data: DashboardPayload }) {
  const maxTechnique = Math.max(...data.techniques.map((item) => item.count), 1);
  const criticalQueue = data.cves
    .filter((item) => ["Critical", "High"].includes(item.severity))
    .sort((left, right) => Number(right.kev) - Number(left.kev))
    .slice(0, 8);
  const trendMaximum = Math.max(
    ...data.cve_trend.map(
      (item) => item.critical + item.high + item.medium + item.low + item.unknown,
    ),
    1,
  );
  const severityTotal = data.severity_distribution.reduce((sum, item) => sum + item.value, 0);
  const iocTotal = data.ioc_distribution.reduce((sum, item) => sum + item.value, 0);
  const assetTotal = data.asset_risk_distribution.reduce((sum, item) => sum + item.value, 0);
  const sourceBuckets = sourceStatusBuckets(data.collection?.sources ?? []);
  const sourceTotal = sourceBuckets.ok + sourceBuckets.warning + sourceBuckets.degraded;

  return (
    <>
      <section className="metrics-grid">
        {data.metrics.map((metric, index) => {
          const Icon = metricIcons[index] || BarChart3;
          return (
            <article className={metricClass(metric)} key={metric.label}>
              <div><Icon size={17} /><span>{metricLabels[metric.label] ?? metric.label}</span></div>
              <strong>{metric.value}</strong>
              <small>{metricDescriptions[metric.delta] ?? metric.delta}</small>
            </article>
          );
        })}
      </section>

      <section className="dashboard-grid dashboard-intelligence-grid">
        <Panel className="trend-panel" title="Tren publikasi CVE · 14 hari" icon={<BarChart3 size={18} />}>
          <div className="trend-chart">
            <div className="chart-legend">
              <span className="critical">Critical</span>
              <span className="high">High</span>
              <span className="medium">Medium</span>
              <span className="low">Low</span>
            </div>
            <div className="trend-bars">
              {data.cve_trend.map((item, index) => {
                const total = item.critical + item.high + item.medium + item.low + item.unknown;
                return (
                  <div
                    className="trend-column"
                    key={item.date}
                    title={`${item.date}: ${total} CVE`}
                  >
                    <div className="trend-bar">
                      <div className="trend-stack" style={{ height: `${(total / trendMaximum) * 100}%` }}>
                        {item.critical > 0 && <i className="critical" style={{ flexGrow: item.critical }} />}
                        {item.high > 0 && <i className="high" style={{ flexGrow: item.high }} />}
                        {item.medium > 0 && <i className="medium" style={{ flexGrow: item.medium }} />}
                        {item.low > 0 && <i className="low" style={{ flexGrow: item.low }} />}
                        {item.unknown > 0 && <i className="unknown" style={{ flexGrow: item.unknown }} />}
                      </div>
                    </div>
                    <span>{index % 3 === 0 || index === data.cve_trend.length - 1 ? item.date.slice(5) : ""}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </Panel>

        <Panel className="risk-panel" title="Profil risiko" icon={<ShieldAlert size={18} />}>
          <div className="risk-distribution">
            {sortedDistribution(data.severity_distribution).map((item) => (
              <div key={item.label}>
                <span>{item.label}</span>
                <div><i className={item.label.toLowerCase()} style={{ width: `${severityTotal ? (item.value / severityTotal) * 100 : 0}%` }} /></div>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
          <div className="asset-posture">
            <div><span>Risiko aset</span><strong>{assetTotal} terpantau</strong></div>
            <div className="asset-risk-strip">
              {data.asset_risk_distribution.map((item) => (
                <i
                  className={item.label.toLowerCase()}
                  key={item.label}
                  style={{ width: `${assetTotal ? (item.value / assetTotal) * 100 : 0}%` }}
                  title={`${item.label}: ${item.value}`}
                />
              ))}
            </div>
            <div className="asset-risk-legend">
              {data.asset_risk_distribution.map((item) => (
                <span key={item.label}>{item.label} <strong>{item.value}</strong></span>
              ))}
            </div>
          </div>
        </Panel>

        <Panel className="priority-panel" title="Kerentanan prioritas" icon={<ShieldAlert size={18} />}>
          <CveTable cves={criticalQueue} />
        </Panel>

        <Panel className="ioc-composition-panel" title="Komposisi indikator" icon={<PieChart size={18} />}>
          <div className="ioc-composition">
            <div className="ioc-donut" style={{ background: conicGradient(data.ioc_distribution) }}>
              <div><strong>{iocTotal}</strong><span>IOC</span></div>
            </div>
            <div className="ioc-legend">
              {data.ioc_distribution.map((item, index) => (
                <div key={item.label}>
                  <i style={{ background: iocColors[index % iocColors.length] }} />
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <Panel className="technique-panel" title="Teknik ATT&CK teramati" icon={<Workflow size={18} />}>
          <div className="bar-list">
            {data.techniques.slice(0, 5).map((item) => (
              <div className="bar-row" key={item.technique_id}>
                <span><strong>{item.technique_id}</strong><small>{item.name}</small></span>
                <div className="bar-track"><div style={{ width: `${(item.count / maxTechnique) * 100}%` }} /></div>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>
        </Panel>

        <Panel className="news-panel" title="Intelijen terbaru" icon={<Globe2 size={18} />}>
          <NewsList items={data.news.slice(0, 5)} />
        </Panel>

        <Panel className="source-health-panel" title="Kesehatan sumber" icon={<RadioTower size={18} />}>
          {data.collection ? (
            <div className="source-health-summary-panel">
              <div className="collection-summary">
                <div>
                  <span>Pengumpulan terakhir</span>
                  <strong>{collectionStatusLabel(data.collection.status)}</strong>
                  <small>
                    {data.collection.finished_at
                      ? formatApiDateTime(data.collection.finished_at, { dateStyle: "medium", timeStyle: "short" })
                      : "Masih berjalan"}
                  </small>
                </div>
                <div>
                  <span>Durasi</span>
                  <strong>{formatDuration(data.collection.duration_seconds)}</strong>
                  <small>{data.collection.degraded_sources} sumber bermasalah</small>
                </div>
              </div>
              <div className="source-health-chart" aria-label={`${sourceBuckets.ok} sumber sehat, ${sourceBuckets.warning} peringatan, ${sourceBuckets.degraded} bermasalah`}>
                <div className="source-health-bar">
                  <i className="ok" style={{ width: `${sourceTotal ? (sourceBuckets.ok / sourceTotal) * 100 : 0}%` }} />
                  <i className="warning" style={{ width: `${sourceTotal ? (sourceBuckets.warning / sourceTotal) * 100 : 0}%` }} />
                  <i className="degraded" style={{ width: `${sourceTotal ? (sourceBuckets.degraded / sourceTotal) * 100 : 0}%` }} />
                </div>
                <div className="source-health-legend">
                  <span><i className="ok" />OK <strong>{sourceBuckets.ok}</strong></span>
                  <span><i className="warning" />Peringatan <strong>{sourceBuckets.warning}</strong></span>
                  <span><i className="degraded" />Bermasalah <strong>{sourceBuckets.degraded}</strong></span>
                </div>
                <a className="source-health-open" href="#/sources">Lihat kesehatan sumber</a>
              </div>
            </div>
          ) : (
            <div className="empty-inline">Belum ada pengumpulan data.</div>
          )}
        </Panel>
      </section>
    </>
  );
}
