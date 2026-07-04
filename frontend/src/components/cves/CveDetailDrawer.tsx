import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  Download,
  ExternalLink,
  FileWarning,
  Link2,
  LoaderCircle,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import {
  fetchCVEAIEnrichment,
  generateCVEAIEnrichment,
  type CVEAIEnrichment,
} from "../../lib/ai";
import type { CVEDetail } from "../../lib/cves";
import { severityClass } from "../ui/CveTable";

type Props = {
  cveId: string;
  csrfToken: string;
  detail: CVEDetail | null;
  error: string;
  loading: boolean;
  onClose: () => void;
};

function formatMetric(value: string) {
  return value || "Unknown";
}

function hostname(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

export function CveDetailDrawer({ cveId, csrfToken, detail, error, loading, onClose }: Props) {
  const [aiEnrichment, setAIEnrichment] = useState<CVEAIEnrichment | null>(null);
  const [aiLoading, setAILoading] = useState(false);
  const [aiError, setAIError] = useState("");

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  useEffect(() => {
    setAIEnrichment(null);
    setAIError("");
    fetchCVEAIEnrichment(cveId)
      .then(setAIEnrichment)
      .catch(() => undefined);
  }, [cveId]);

  async function runAIInvestigation() {
    setAILoading(true);
    setAIError("");
    try {
      setAIEnrichment(await generateCVEAIEnrichment(cveId, csrfToken));
    } catch (reason) {
      setAIError(reason instanceof Error ? reason.message : "AI investigation gagal.");
    } finally {
      setAILoading(false);
    }
  }

  const officialProductKnown = Boolean(
    detail?.product && detail.product.trim().toLowerCase() !== "unknown",
  );
  const displayedVendor = officialProductKnown
    ? detail?.vendor
    : aiEnrichment?.product_inference.vendor || detail?.vendor;
  const displayedProduct = officialProductKnown
    ? detail?.product
    : aiEnrichment?.product_inference.product || detail?.product;

  const cvssMetrics = detail?.cvss
    ? [
        ["Attack Vector", detail.cvss.attack_vector],
        ["Attack Complexity", detail.cvss.attack_complexity],
        ["Privileges Required", detail.cvss.privileges_required],
        ["User Interaction", detail.cvss.user_interaction],
        ["Scope", detail.cvss.scope],
        ["Confidentiality", detail.cvss.confidentiality_impact],
        ["Integrity", detail.cvss.integrity_impact],
        ["Availability", detail.cvss.availability_impact],
      ]
    : [];

  return (
    <div className="cve-detail-backdrop" onMouseDown={onClose}>
      <aside
        aria-labelledby="cve-detail-title"
        aria-modal="true"
        className="cve-detail-drawer"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
      >
        <header className="cve-detail-header">
          <div>
            <span className="eyebrow">CVE Investigation</span>
            <h2 id="cve-detail-title">{cveId}</h2>
          </div>
          <div className="cve-detail-header-actions">
            <a
              aria-label={`Download PDF ${cveId}`}
              download
              href={`/api/cves/${encodeURIComponent(cveId)}/pdf`}
              title="Download PDF"
            >
              <Download size={19} />
            </a>
            <button aria-label="Tutup detail CVE" onClick={onClose} title="Tutup" type="button"><X size={20} /></button>
          </div>
        </header>

        {loading && (
          <div aria-live="polite" className="cve-detail-state loading" role="status">
            <LoaderCircle aria-hidden="true" className="loading-spinner" size={32} />
            <span>Mengambil detail dari cache/NVD...</span>
          </div>
        )}
        {error && <div className="cve-detail-state error"><AlertTriangle size={20} />{error}</div>}

        {detail && (
          <div className="cve-detail-content">
            <section className="cve-summary">
              <div className="cve-title-row">
                <div>
                  <h3>{detail.title}</h3>
                  <p>
                    {displayedVendor}{displayedProduct ? ` / ${displayedProduct}` : ""}
                    {!officialProductKnown && aiEnrichment && (
                      <span className="ai-inferred-badge">
                        AI inferred {Math.round(aiEnrichment.product_inference.confidence * 100)}%
                      </span>
                    )}
                  </p>
                </div>
                <span className={severityClass(detail.severity)}>{detail.severity}</span>
              </div>
              <p className="cve-description">{detail.description}</p>
              <div className="cve-meta">
                <span>Published <strong>{new Date(detail.published_at).toLocaleDateString("id-ID")}</strong></span>
                <span>Source <strong>{detail.detail_source}</strong></span>
                <span>Weakness <strong>{detail.weaknesses.join(", ") || "Not available"}</strong></span>
              </div>
            </section>

            <section className="cve-detail-section deterministic-analysis">
              <div className="root-cause-block">
                <div className="section-heading"><Bug size={18} /><h3>Root Cause</h3></div>
                <div className="root-cause-heading">
                  <div>
                    <span>Category</span>
                    <strong>{detail.root_cause.category}</strong>
                  </div>
                  <span className={`analysis-confidence ${detail.root_cause.confidence.toLowerCase()}`}>
                    {detail.root_cause.confidence} confidence
                  </span>
                </div>
                <p>{detail.root_cause.summary}</p>
                <div className="root-cause-meta">
                  {detail.root_cause.weaknesses.map((item) => <code key={item}>{item}</code>)}
                  <span>Basis: {detail.root_cause.basis}</span>
                </div>
              </div>
              <div className="mitre-analysis-block">
                <div className="section-heading"><Network size={18} /><h3>Potential MITRE ATT&CK</h3></div>
                <p className="analysis-disclaimer">
                  Heuristic relationship from CVSS, CWE, and exploit conditions. This is not threat-actor attribution.
                </p>
                {detail.mitre_techniques.length > 0 ? (
                  <div className="mitre-mapping-list">
                    {detail.mitre_techniques.map((item) => (
                      <a href={item.url} key={item.technique_id} rel="noopener noreferrer" target="_blank">
                        <span className="mitre-id">{item.technique_id}</span>
                        <span>
                          <strong>{item.name}</strong>
                          <small>{item.tactic} · {item.rationale}</small>
                        </span>
                        <span className={`analysis-confidence ${item.confidence.toLowerCase()}`}>{item.confidence}</span>
                        <ExternalLink size={14} />
                      </a>
                    ))}
                  </div>
                ) : (
                  <p className="detail-empty">Belum ada ATT&CK relationship yang dapat dipetakan secara defensible.</p>
                )}
              </div>
            </section>

            <section className="cve-detail-section ai-enrichment-section">
              <div className="ai-enrichment-heading">
                <div className="section-heading"><Sparkles size={18} /><h3>AI Investigation</h3></div>
                <button disabled={aiLoading} onClick={() => void runAIInvestigation()} type="button">
                  {aiLoading ? <LoaderCircle className="loading-spinner" size={16} /> : aiEnrichment ? <RefreshCw size={16} /> : <Sparkles size={16} />}
                  {aiLoading ? "Analyzing" : aiEnrichment ? "Refresh analysis" : "Run analysis"}
                </button>
              </div>
              {aiError && <div className="ai-inline-error"><AlertTriangle size={15} />{aiError}</div>}
              {aiLoading && !aiEnrichment && (
                <div className="ai-investigation-loading" role="status">
                  <LoaderCircle className="loading-spinner" size={24} />
                  <span>PicoClaw sedang mengkorelasikan evidence...</span>
                </div>
              )}
              {aiEnrichment ? (
                <div className="ai-enrichment-content">
                  <div className="ai-summary-block">
                    <span>Analyst summary</span>
                    <p>{aiEnrichment.executive_summary || "Summary tidak tersedia."}</p>
                  </div>
                  <div className="ai-product-resolution">
                    <div>
                      <span>Product resolution</span>
                      <strong>{aiEnrichment.product_inference.vendor} / {aiEnrichment.product_inference.product}</strong>
                      <small>{aiEnrichment.product_inference.versions.join(", ") || "Affected version belum terkonfirmasi"}</small>
                    </div>
                    <div className="ai-confidence">
                      <strong>{Math.round(aiEnrichment.product_inference.confidence * 100)}%</strong>
                      <span>confidence</span>
                    </div>
                  </div>
                  <div className="ai-analysis-grid">
                    <div><span>Attack path</span>{aiEnrichment.attack_path.length ? <ul>{aiEnrichment.attack_path.map((item) => <li key={item}>{item}</li>)}</ul> : <p>Belum teridentifikasi.</p>}</div>
                    <div><span>Business impact</span>{aiEnrichment.business_impact.length ? <ul>{aiEnrichment.business_impact.map((item) => <li key={item}>{item}</li>)}</ul> : <p>Belum teridentifikasi.</p>}</div>
                    <div><span>Detection guidance</span>{aiEnrichment.detection_guidance.length ? <ul>{aiEnrichment.detection_guidance.map((item) => <li key={item}>{item}</li>)}</ul> : <p>Belum tersedia.</p>}</div>
                    <div><span>Mitigation priority</span>{aiEnrichment.mitigation.length ? <ul>{aiEnrichment.mitigation.map((item) => <li key={item}>{item}</li>)}</ul> : <p>Belum tersedia.</p>}</div>
                  </div>
                  {aiEnrichment.product_inference.evidence.length > 0 && (
                    <div className="ai-evidence">
                      <span>Product evidence</span>
                      <ul>{aiEnrichment.product_inference.evidence.map((item) => <li key={item}>{item}</li>)}</ul>
                    </div>
                  )}
                  <footer>
                    AI-generated by {aiEnrichment.provider || "PicoClaw"} / {aiEnrichment.model || "default"} at {new Date(aiEnrichment.generated_at).toLocaleString("id-ID")}. Verify before action.
                  </footer>
                </div>
              ) : !aiLoading && (
                <p className="detail-empty">Jalankan PicoClaw untuk product resolution, attack path, impact, detection, dan mitigation synthesis.</p>
              )}
            </section>

            <section className="cve-detail-section">
              <div className="section-heading"><ShieldAlert size={18} /><h3>CVSS Matrix</h3></div>
              <div className="cvss-overview">
                <div className={`cvss-score cvss-${detail.severity.toLowerCase()}`}>
                  <strong>{detail.cvss_score.toFixed(1)}</strong>
                  <span>CVSS {detail.cvss?.version || ""}</span>
                </div>
                <div className="cvss-vector">
                  <span>Vector</span>
                  <code>{detail.cvss?.vector || "CVSS vector is not available"}</code>
                  <div>
                    <span>Exploitability <strong>{detail.cvss?.exploitability_score ?? "-"}</strong></span>
                    <span>Impact <strong>{detail.cvss?.impact_score ?? "-"}</strong></span>
                  </div>
                </div>
              </div>
              {cvssMetrics.length > 0 ? (
                <div className="cvss-matrix">
                  {cvssMetrics.map(([label, value]) => (
                    <div key={label}><span>{label}</span><strong>{formatMetric(value)}</strong></div>
                  ))}
                </div>
              ) : <p className="detail-empty">CVSS matrix belum tersedia dari sumber.</p>}
            </section>

            <section className="cve-detail-section">
              <div className="section-heading"><FileWarning size={18} /><h3>Exploitation Status</h3></div>
              <div className={detail.exploit_status.known_exploited ? "exploit-banner active" : "exploit-banner"}>
                {detail.exploit_status.known_exploited ? <AlertTriangle size={20} /> : <CheckCircle2 size={20} />}
                <div>
                  <strong>{detail.exploit_status.known_exploited ? "Known exploited in the wild" : "Belum tercatat di CISA KEV"}</strong>
                  <span>
                    {detail.exploit_status.date_added ? `KEV sejak ${detail.exploit_status.date_added}` : "Status berdasarkan cache NVD/CISA saat ini"}
                  </span>
                </div>
              </div>
              <dl className="exploit-facts">
                <div><dt>KEV</dt><dd>{detail.kev ? "Yes" : "No"}</dd></div>
                <div><dt>Ransomware use</dt><dd>{detail.exploit_status.ransomware_use}</dd></div>
                <div><dt>Action due</dt><dd>{detail.exploit_status.action_due || "-"}</dd></div>
              </dl>
            </section>

            <section className="cve-detail-section">
              <div className="section-heading"><Bug size={18} /><h3>Affected Products</h3></div>
              <div className="detail-table-scroll">
                <table>
                  <thead><tr><th>Vendor</th><th>Product</th><th>Version</th><th>Range</th></tr></thead>
                  <tbody>
                    {detail.affected_products.map((item, index) => (
                      <tr key={`${item.vendor}-${item.product}-${item.version}-${index}`}>
                        <td>{item.vendor}</td><td>{item.product}</td><td>{item.version}</td><td>{item.version_range || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="cve-detail-section remediation-section">
              <div>
                <div className="section-heading"><CheckCircle2 size={18} /><h3>Mitigation</h3></div>
                {detail.mitigation.length > 0 ? (
                  <div className="remediation-list">
                    {detail.mitigation.map((item) => (
                      <div key={`${item.source}-${item.text}`}>
                        <p>{item.text}</p>
                        {item.url ? (
                          <a href={item.url} rel="noopener noreferrer" target="_blank">
                            {item.source}<ExternalLink size={12} />
                          </a>
                        ) : <span>{item.source}</span>}
                      </div>
                    ))}
                  </div>
                ) : <p className="detail-empty">Belum ada mitigation terverifikasi dari sumber yang tersedia.</p>}
              </div>
              <div>
                <div className="section-heading"><AlertTriangle size={18} /><h3>Workaround</h3></div>
                {detail.workarounds.length > 0 ? (
                  <div className="remediation-list">
                    {detail.workarounds.map((item) => (
                      <div key={`${item.source}-${item.text}`}>
                        <p>{item.text}</p>
                        {item.url ? (
                          <a href={item.url} rel="noopener noreferrer" target="_blank">
                            {item.source}<ExternalLink size={12} />
                          </a>
                        ) : <span>{item.source}</span>}
                      </div>
                    ))}
                  </div>
                ) : <p className="detail-empty">Belum ada workaround terverifikasi dari CNA/vendor.</p>}
              </div>
              {detail.remediation_sources.length > 0 && (
                <div className="remediation-resources">
                  <span>Remediation resources</span>
                  <div>
                    {detail.remediation_sources.slice(0, 12).map((item) => (
                      <a href={item.url} key={item.url} rel="noopener noreferrer" target="_blank">
                        {item.tags[0] || item.source || hostname(item.url)}<ExternalLink size={12} />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </section>

            <section className="cve-detail-section">
              <div className="section-heading"><Server size={18} /><h3>Related Assets</h3></div>
              {detail.related_assets.length > 0 ? (
                <div className="related-list">
                  {detail.related_assets.map((asset) => (
                    <div key={asset.id}>
                      <strong>{asset.name}</strong>
                      <span>{asset.asset_type} · {asset.os_version || "Version unknown"} · {asset.owner || "No owner"}</span>
                      <span className={severityClass(asset.risk)}>{asset.risk}</span>
                    </div>
                  ))}
                </div>
              ) : <p className="detail-empty">Tidak ada asset inventory yang terhubung ke CVE ini.</p>}
            </section>

            <section className="cve-detail-section">
              <div className="section-heading"><Bug size={18} /><h3>Related IOC</h3></div>
              {detail.related_iocs.length > 0 ? (
                <div className="detail-table-scroll">
                  <table>
                    <thead><tr><th>Indicator</th><th>Type</th><th>Threat</th><th>Source</th></tr></thead>
                    <tbody>
                      {detail.related_iocs.map((ioc) => (
                        <tr key={`${ioc.type}-${ioc.indicator}`}>
                          <td><code>{ioc.indicator}</code></td><td>{ioc.type}</td><td>{ioc.threat}</td><td>{ioc.source}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <p className="detail-empty">Belum ada IOC yang memiliki relasi terverifikasi dengan CVE ini.</p>}
            </section>

            {detail.related_news.length > 0 && (
              <section className="cve-detail-section">
                <div className="section-heading"><Link2 size={18} /><h3>Related Intelligence</h3></div>
                <div className="reference-list">
                  {detail.related_news.map((item) => (
                    <a href={item.url} key={item.url} rel="noopener noreferrer" target="_blank">
                      <span><strong>{item.title}</strong><small>{item.source}</small></span><ExternalLink size={15} />
                    </a>
                  ))}
                </div>
              </section>
            )}

            <section className="cve-detail-section">
              <div className="section-heading"><Link2 size={18} /><h3>References</h3></div>
              {detail.references.length > 0 ? (
                <div className="reference-list">
                  {detail.references.map((item) => (
                    <a href={item.url} key={item.url} rel="noopener noreferrer" target="_blank">
                      <span>
                        <strong>{item.tags[0] || item.source || hostname(item.url)}</strong>
                        <small>{hostname(item.url)}</small>
                      </span>
                      <ExternalLink size={15} />
                    </a>
                  ))}
                </div>
              ) : <p className="detail-empty">Reference link belum tersedia dari sumber.</p>}
            </section>
          </div>
        )}
      </aside>
    </div>
  );
}
