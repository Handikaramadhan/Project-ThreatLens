import { AlertTriangle, CheckCircle2, Clock3, RadioTower, Search } from "lucide-react";
import { useMemo, useState } from "react";
import type { CollectionSummary, SourceStatusItem } from "../../lib/api";
import { formatApiDateTime } from "../../lib/datetime";
import { collectionStatusLabel, formatDuration, sourceHealthClass, sourceStatusBuckets, sourceStatusLabel } from "../../lib/sourceHealth";
import { Panel } from "../ui/Panel";

function statusTone(item: SourceStatusItem) {
  if (item.status === "ok") return "ok";
  if (item.status === "error" || item.status === "stale") return "degraded";
  return "warning";
}

function statusIcon(item: SourceStatusItem) {
  const tone = statusTone(item);
  if (tone === "ok") return <CheckCircle2 size={15} />;
  if (tone === "degraded") return <AlertTriangle size={15} />;
  return <Clock3 size={15} />;
}

export function SourceHealthView({ collection }: { collection: CollectionSummary | null }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("All");
  const buckets = sourceStatusBuckets(collection?.sources ?? []);
  const sources = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (collection?.sources ?? []).filter((source) => {
      const matchesStatus = status === "All" || source.status === status;
      const matchesQuery = !needle || [
        source.name,
        source.id,
        source.category,
        source.status,
        source.message,
      ].some((value) => value.toLowerCase().includes(needle));
      return matchesStatus && matchesQuery;
    });
  }, [collection?.sources, query, status]);

  return (
    <section className="source-health-page">
      <div className="source-health-overview">
        <article className="source-health-stat ok">
          <span>OK</span>
          <strong>{buckets.ok}</strong>
        </article>
        <article className="source-health-stat warning">
          <span>Warning</span>
          <strong>{buckets.warning}</strong>
        </article>
        <article className="source-health-stat degraded">
          <span>Degraded</span>
          <strong>{buckets.degraded}</strong>
        </article>
        <article className="source-health-stat">
          <span>Duration</span>
          <strong>{formatDuration(collection?.duration_seconds ?? null)}</strong>
        </article>
      </div>

      <div className="view-toolbar">
        <label className="search-control">
          <Search size={16} />
          <input aria-label="Cari source" autoComplete="off" name="source_query" onChange={(event) => setQuery(event.target.value)} placeholder="Cari source…" value={query} />
        </label>
        <select aria-label="Filter status source" name="source_status" onChange={(event) => setStatus(event.target.value)} value={status}>
          {["All", "ok", "fallback", "skipped", "error", "stale"].map((item) => (
            <option key={item} value={item}>{item === "All" ? "Semua status" : sourceStatusLabel(item)}</option>
          ))}
        </select>
        <span className="result-count">{sources.length} source</span>
      </div>

      <Panel title="Source Health Detail" icon={<RadioTower size={18} />} wide>
        {collection ? (
          <>
            <div className="source-health-run-summary">
              <div><span>Status pengumpulan</span><strong>{collectionStatusLabel(collection.status)}</strong></div>
              <div>
                <span>Started</span>
                <strong>{collection.started_at ? formatApiDateTime(collection.started_at, { dateStyle: "medium", timeStyle: "short" }) : "-"}</strong>
              </div>
              <div>
                <span>Finished</span>
                <strong>{collection.finished_at ? formatApiDateTime(collection.finished_at, { dateStyle: "medium", timeStyle: "short" }) : "Still running"}</strong>
              </div>
              <div><span>Degraded</span><strong>{collection.degraded_sources}</strong></div>
            </div>
            <div className="table-scroll source-health-table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Count</th>
                    <th>Failures</th>
                    <th>Last success</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map((source) => (
                    <tr key={source.id}>
                      <td>
                        <div className="source-name-cell">
                          <strong>{source.name}</strong>
                          <span>{source.id}</span>
                        </div>
                      </td>
                      <td>{source.category}</td>
                      <td>
                        <span className={`${sourceHealthClass(source)} source-health-inline`}>
                          {statusIcon(source)}
                          {sourceStatusLabel(source.status)}
                        </span>
                      </td>
                      <td>{source.count ?? "-"}</td>
                      <td>{source.consecutive_failures}</td>
                      <td>
                        {source.last_success_at
                          ? formatApiDateTime(source.last_success_at, { dateStyle: "medium", timeStyle: "short" })
                          : "Never in retained runs"}
                      </td>
                      <td className="source-message-cell">{source.message || "-"}</td>
                    </tr>
                  ))}
                  {sources.length === 0 && (
                    <tr><td className="table-state" colSpan={7}>Source tidak ditemukan.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <div className="empty-inline">Belum ada collection run.</div>
        )}
      </Panel>
    </section>
  );
}
