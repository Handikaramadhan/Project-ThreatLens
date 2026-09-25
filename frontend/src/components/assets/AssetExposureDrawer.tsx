import { AlertTriangle, CheckCircle2, ExternalLink, Info, LoaderCircle, Save, ShieldAlert, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { Asset, AssetExposure, AssetExposureStatus } from "../../lib/assets";
import { formatApiDate } from "../../lib/datetime";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { severityClass } from "../ui/CveTable";

type Props = {
  asset: Asset;
  exposures: AssetExposure[];
  loading: boolean;
  error: string;
  onClose: () => void;
  onReviewUpdate: (cveId: string, status: AssetExposureStatus, reviewNote: string) => Promise<void>;
};

const exposureStatuses: { value: AssetExposureStatus; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "validated", label: "Validated" },
  { value: "false_positive", label: "False positive" },
  { value: "accepted_risk", label: "Accepted risk" },
  { value: "remediated", label: "Remediated" },
];

const confidenceClass = (confidence: AssetExposure["confidence"]) => (
  confidence === "High" ? "high" : confidence === "Medium" ? "medium" : "low"
);

const affectedVersion = (item: AssetExposure) => {
  if (item.affected_version_range) return item.affected_version_range;
  if (item.affected_version) return item.affected_version;
  return "Not specified";
};

export function AssetExposureDrawer({ asset, exposures, loading, error, onClose, onReviewUpdate }: Props) {
  const [drafts, setDrafts] = useState<Record<string, { status: AssetExposureStatus; reviewNote: string }>>({});
  const [savingCve, setSavingCve] = useState<string | null>(null);
  const [reviewError, setReviewError] = useState("");
  const dialogRef = useRef<HTMLElement>(null);
  useDialogFocus(dialogRef, { onClose });

  useEffect(() => {
    setDrafts(Object.fromEntries(
      exposures.map((item) => [item.cve_id, { status: item.status, reviewNote: item.review_note }])
    ));
  }, [exposures]);

  function setDraft(cveId: string, patch: Partial<{ status: AssetExposureStatus; reviewNote: string }>) {
    setDrafts((current) => ({
      ...current,
      [cveId]: {
        status: current[cveId]?.status ?? "open",
        reviewNote: current[cveId]?.reviewNote ?? "",
        ...patch,
      },
    }));
  }

  async function saveReview(item: AssetExposure) {
    const draft = drafts[item.cve_id] ?? { status: item.status, reviewNote: item.review_note };
    setSavingCve(item.cve_id);
    setReviewError("");
    try {
      await onReviewUpdate(item.cve_id, draft.status, draft.reviewNote);
    } catch (reason) {
      setReviewError(reason instanceof Error ? reason.message : "Gagal menyimpan review exposure.");
    } finally {
      setSavingCve(null);
    }
  }

  return (
    <div className="cve-detail-backdrop" onMouseDown={onClose}>
      <aside
        aria-labelledby="asset-exposure-title"
        aria-modal="true"
        className="cve-detail-drawer asset-exposure-drawer"
        onMouseDown={(event) => event.stopPropagation()}
        ref={dialogRef}
        role="dialog"
      >
        <header className="cve-detail-header">
          <div>
            <span>Asset exposure</span>
            <h2 id="asset-exposure-title">{asset.name}</h2>
            <p>
              {asset.asset_type}
              {asset.product ? ` · ${[asset.vendor, asset.product, asset.version].filter(Boolean).join(" ")}` : ""}
              {asset.os_version ? ` · ${asset.os_version}` : ""}
              {asset.internet_exposed ? " · Internet exposed" : ""}
            </p>
          </div>
          <button aria-label="Close exposure detail" onClick={onClose} type="button">
            <X size={18} />
          </button>
        </header>

        {loading && (
          <div aria-live="polite" className="cve-detail-state loading" role="status">
            <LoaderCircle aria-hidden="true" className="loading-spinner" size={32} />
            <span>Mengambil exposure asset…</span>
          </div>
        )}
        {error && <div className="cve-detail-state error"><AlertTriangle size={20} />{error}</div>}

        {!loading && !error && (
          <div className="asset-exposure-list">
            {reviewError && <div className="form-error" role="alert">{reviewError}</div>}
            {exposures.length > 0 && (
              <div className="asset-exposure-summary">
                <ShieldAlert size={18} />
                <div>
                  <strong>{exposures.length} matched CVE</strong>
                  <span>Confidence is based on deterministic metadata matching, not AI inference.</span>
                </div>
              </div>
            )}
            {exposures.length === 0 && (
              <div className="empty-inline">
                Tidak ada CVE yang match dengan metadata asset ini.
              </div>
            )}
            {exposures.map((item) => (
              <article className="asset-exposure-card" key={item.cve_id}>
                <div className="asset-exposure-card-header">
                  <div>
                    <strong>{item.cve_id}</strong>
                    <span>{item.title}</span>
                  </div>
                  <div className="asset-exposure-badges">
                    <span className={`asset-status asset-status-${item.status.replace("_", "-")}`}>
                      {item.status.replace("_", " ")}
                    </span>
                    <span className={`asset-confidence ${confidenceClass(item.confidence)}`}>
                      {item.confidence} confidence
                    </span>
                    <span className={severityClass(item.severity)}>{item.severity}</span>
                  </div>
                </div>
                <div className="asset-score-row">
                  <div className="asset-score-meter" aria-label={`Matching score ${item.matching_score} out of 100`}>
                    <span style={{ width: `${item.matching_score}%` }} />
                  </div>
                  <strong>{item.matching_score}/100</strong>
                </div>
                <p className="asset-exposure-reason">{item.reason}</p>
                <dl className="asset-exposure-facts">
                  <div><dt>Match type</dt><dd>{item.match_type}</dd></div>
                  <div><dt>Affected product</dt><dd>{[item.affected_vendor, item.affected_product].filter(Boolean).join(" ") || "Unknown"}</dd></div>
                  <div><dt>Affected version</dt><dd>{affectedVersion(item)}</dd></div>
                  <div><dt>Risk</dt><dd>{item.risk}</dd></div>
                  <div><dt>Status</dt><dd>{item.status.replace("_", " ")}</dd></div>
                  <div><dt>Published</dt><dd>{formatApiDate(item.published_at)}</dd></div>
                  <div><dt>KEV</dt><dd>{item.kev ? "Yes" : "No"}</dd></div>
                  <div><dt>Reviewed</dt><dd>{item.reviewed_at ? `${formatApiDate(item.reviewed_at)}${item.reviewed_by ? ` by ${item.reviewed_by}` : ""}` : "Not reviewed"}</dd></div>
                </dl>
                <div className="asset-exposure-explain-grid">
                  <section>
                    <h3><CheckCircle2 size={15} />Evidence</h3>
                    <ul>
                      {item.evidence.map((entry) => <li key={entry}>{entry}</li>)}
                    </ul>
                  </section>
                  <section>
                    <h3><Info size={15} />Limitations</h3>
                    {item.limitations.length > 0 ? (
                      <ul>
                        {item.limitations.map((entry) => <li key={entry}>{entry}</li>)}
                      </ul>
                    ) : (
                      <p>No major matching limitation was detected from available metadata.</p>
                    )}
                  </section>
                </div>
                <div className="asset-exposure-review">
                  <label>
                    Review status
                    <select
                      name={`review_status_${item.cve_id}`}
                      onChange={(event) => setDraft(item.cve_id, { status: event.target.value as AssetExposureStatus })}
                      value={drafts[item.cve_id]?.status ?? item.status}
                    >
                      {exposureStatuses.map((status) => (
                        <option key={status.value} value={status.value}>{status.label}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Review note
                    <textarea
                      maxLength={500}
                      name={`review_note_${item.cve_id}`}
                      onChange={(event) => setDraft(item.cve_id, { reviewNote: event.target.value })}
                      placeholder="Contoh: package tidak terinstall, sudah patch, risiko diterima sampai maintenance window…"
                      value={drafts[item.cve_id]?.reviewNote ?? item.review_note}
                    />
                  </label>
                  <button disabled={savingCve === item.cve_id} onClick={() => void saveReview(item)} type="button">
                    <Save size={15} />{savingCve === item.cve_id ? "Menyimpan…" : "Save review"}
                  </button>
                </div>
                <div className="asset-exposure-actions">
                  <a href={`#/cve?selected=${encodeURIComponent(item.cve_id)}`} title={`Open ${item.cve_id}`}>
                    <ExternalLink size={15} />Open CVE detail
                  </a>
                </div>
              </article>
            ))}
          </div>
        )}
      </aside>
    </div>
  );
}
