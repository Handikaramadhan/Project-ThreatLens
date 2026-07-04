import { ChevronLeft, ChevronRight, Search, Shield } from "lucide-react";
import { useEffect, useState } from "react";
import type { CVEItem } from "../../lib/api";
import { fetchCveDetail, fetchCves, type CVEDetail, type CVEListItem } from "../../lib/cves";
import { CveDetailDrawer } from "../cves/CveDetailDrawer";
import { CveTable } from "../ui/CveTable";
import { Panel } from "../ui/Panel";

const PAGE_LIMIT = 500;

export function CveView({ cves: initialCves, csrfToken }: { cves: CVEItem[]; csrfToken: string }) {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [severity, setSeverity] = useState("All");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<CVEListItem[]>(initialCves);
  const [total, setTotal] = useState(initialCves.length);
  const [pages, setPages] = useState(1);
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CVEDetail | null>(null);
  const [detailError, setDetailError] = useState("");
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedQuery(query.trim());
      setPage(1);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    let active = true;
    setListLoading(true);
    setListError("");
    fetchCves(debouncedQuery, severity, page, PAGE_LIMIT)
      .then((payload) => {
        if (!active) return;
        setItems(payload.items);
        setTotal(payload.total);
        setPages(payload.pages);
        if (payload.page !== page) setPage(payload.page);
      })
      .catch((reason) => {
        if (active) setListError(reason instanceof Error ? reason.message : "Gagal memuat CVE.");
      })
      .finally(() => {
        if (active) setListLoading(false);
      });
    return () => {
      active = false;
    };
  }, [debouncedQuery, severity, page]);

  useEffect(() => {
    if (!selectedId) return;
    let active = true;
    setDetail(null);
    setDetailError("");
    setDetailLoading(true);
    fetchCveDetail(selectedId)
      .then((payload) => {
        if (active) setDetail(payload);
      })
      .catch((reason) => {
        if (active) setDetailError(reason instanceof Error ? reason.message : "Gagal memuat detail CVE.");
      })
      .finally(() => {
        if (active) setDetailLoading(false);
      });
    return () => {
      active = false;
    };
  }, [selectedId]);

  const rangeStart = total === 0 ? 0 : (page - 1) * PAGE_LIMIT + 1;
  const rangeEnd = Math.min(page * PAGE_LIMIT, total);

  return (
    <section className="view-grid">
      <div className="view-toolbar cve-toolbar">
        <label className="search-control">
          <Search size={16} />
          <input onChange={(event) => setQuery(event.target.value)} placeholder="Cari CVE, vendor, atau product" type="search" value={query} />
        </label>
        <select
          onChange={(event) => {
            setSeverity(event.target.value);
            setPage(1);
          }}
          value={severity}
        >
          {["All", "Critical", "High", "Medium", "Low", "Unknown"].map((item) => (
            <option key={item} value={item}>{item === "All" ? "Semua severity" : item}</option>
          ))}
        </select>
        <span className="result-count">{rangeStart}-{rangeEnd} dari {total} CVE</span>
        <div className="pagination-controls">
          <button aria-label="Halaman sebelumnya" disabled={page <= 1 || listLoading} onClick={() => setPage((value) => value - 1)} title="Sebelumnya" type="button">
            <ChevronLeft size={17} />
          </button>
          <span>{page} / {pages}</span>
          <button aria-label="Halaman berikutnya" disabled={page >= pages || listLoading} onClick={() => setPage((value) => value + 1)} title="Berikutnya" type="button">
            <ChevronRight size={17} />
          </button>
        </div>
      </div>
      {listError && <div className="form-error" role="alert">{listError}</div>}
      <Panel title="CVE List" icon={<Shield size={18} />} wide>
        {listLoading && items.length === 0
          ? <div className="table-state">Memuat CVE...</div>
          : <CveTable cves={items} onSelect={setSelectedId} selectedId={selectedId || undefined} />}
      </Panel>
      {selectedId && (
        <CveDetailDrawer
          cveId={selectedId}
          csrfToken={csrfToken}
          detail={detail}
          error={detailError}
          loading={detailLoading}
          onClose={() => setSelectedId(null)}
        />
      )}
    </section>
  );
}
