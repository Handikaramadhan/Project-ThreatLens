import { Pencil, Plus, RefreshCw, Search, Server, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  createAsset,
  deleteAsset,
  fetchAssetExposures,
  fetchAssets,
  recalculateAssetExposures,
  updateAssetExposure,
  updateAsset,
  type Asset,
  type AssetExposure,
  type AssetExposureStatus,
  type AssetInput,
} from "../../lib/assets";
import { AssetExposureDrawer } from "../assets/AssetExposureDrawer";
import { AssetFormModal } from "../assets/AssetFormModal";
import { DeleteAssetModal } from "../assets/DeleteAssetModal";
import { severityClass } from "../ui/CveTable";
import { Panel } from "../ui/Panel";

type Props = {
  csrfToken: string;
  onAssetsChanged: () => void;
};

function assetIdFromHash(): number | null {
  const [, queryString = ""] = window.location.hash.split("?");
  const raw = new URLSearchParams(queryString).get("asset");
  if (!raw) return null;
  const assetId = Number(raw);
  return Number.isInteger(assetId) && assetId > 0 ? assetId : null;
}

function currentViewHash() {
  return window.location.hash.replace(/^#\/?/, "").split("?")[0];
}

export function AssetsView({ csrfToken, onAssetsChanged }: Props) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState("");
  const [notice, setNotice] = useState("");
  const [editingAsset, setEditingAsset] = useState<Asset | null | undefined>(undefined);
  const [deletingAsset, setDeletingAsset] = useState<Asset | null>(null);
  const [exposureAsset, setExposureAsset] = useState<Asset | null>(null);
  const [exposures, setExposures] = useState<AssetExposure[]>([]);
  const [exposuresLoading, setExposuresLoading] = useState(false);
  const [exposuresError, setExposuresError] = useState("");
  const [modalError, setModalError] = useState("");
  const [busy, setBusy] = useState(false);

  async function loadAssets() {
    setLoading(true);
    setPageError("");
    try {
      setAssets(await fetchAssets());
    } catch (reason) {
      setPageError(reason instanceof Error ? reason.message : "Gagal memuat asset.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadAssets();
  }, []);

  useEffect(() => {
    function handleHashChange() {
      if (currentViewHash() !== "assets") return;
      const assetId = assetIdFromHash();
      if (assetId === null) {
        setExposureAsset(null);
        return;
      }
      const asset = assets.find((item) => item.id === assetId);
      if (asset && exposureAsset?.id !== asset.id) {
        void openExposures(asset, false);
      }
    }
    window.addEventListener("hashchange", handleHashChange);
    handleHashChange();
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [assets, exposureAsset?.id]);

  const filteredAssets = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return assets;
    return assets.filter((asset) =>
      [
        asset.name,
        asset.asset_type,
        asset.os_version,
        asset.vendor,
        asset.product,
        asset.version,
        asset.environment,
        asset.owner,
        asset.risk,
        asset.criticality,
      ]
        .some((value) => value.toLowerCase().includes(needle))
    );
  }, [assets, query]);

  function openCreate() {
    setModalError("");
    setNotice("");
    setEditingAsset(null);
  }

  function openEdit(asset: Asset) {
    setModalError("");
    setNotice("");
    setEditingAsset(asset);
  }

  async function saveAsset(payload: AssetInput) {
    setBusy(true);
    setModalError("");
    try {
      if (editingAsset) {
        const updated = await updateAsset(editingAsset.id, payload, csrfToken);
        setAssets((current) => current.map((asset) => asset.id === updated.id ? updated : asset));
        setNotice(`Asset ${updated.name} berhasil diperbarui.`);
      } else {
        const created = await createAsset(payload, csrfToken);
        setAssets((current) => [...current, created].sort((a, b) => a.name.localeCompare(b.name)));
        setNotice(`Asset ${created.name} berhasil ditambahkan.`);
      }
      setEditingAsset(undefined);
      onAssetsChanged();
    } catch (reason) {
      setModalError(reason instanceof Error ? reason.message : "Gagal menyimpan asset.");
    } finally {
      setBusy(false);
    }
  }

  async function removeAsset() {
    if (!deletingAsset) return;
    setBusy(true);
    setModalError("");
    try {
      await deleteAsset(deletingAsset.id, csrfToken);
      setAssets((current) => current.filter((asset) => asset.id !== deletingAsset.id));
      setNotice(`Asset ${deletingAsset.name} berhasil dihapus.`);
      setDeletingAsset(null);
      onAssetsChanged();
    } catch (reason) {
      setModalError(reason instanceof Error ? reason.message : "Gagal menghapus asset.");
    } finally {
      setBusy(false);
    }
  }

  async function recalculateExposures() {
    setBusy(true);
    setPageError("");
    setNotice("");
    try {
      const result = await recalculateAssetExposures(csrfToken);
      await loadAssets();
      onAssetsChanged();
      setNotice(`Exposure asset dihitung ulang: ${result.matching_cve} match.`);
    } catch (reason) {
      setPageError(reason instanceof Error ? reason.message : "Gagal menghitung ulang exposure asset.");
    } finally {
      setBusy(false);
    }
  }

  async function openExposures(asset: Asset, updateHash = true) {
    if (updateHash) {
      window.location.hash = `/assets?asset=${asset.id}`;
    }
    setExposureAsset(asset);
    setExposures([]);
    setExposuresError("");
    setExposuresLoading(true);
    try {
      setExposures(await fetchAssetExposures(asset.id));
    } catch (reason) {
      setExposuresError(reason instanceof Error ? reason.message : "Gagal memuat exposure asset.");
    } finally {
      setExposuresLoading(false);
    }
  }

  async function updateExposureReview(cveId: string, status: AssetExposureStatus, reviewNote: string) {
    if (!exposureAsset) return;
    const updated = await updateAssetExposure(exposureAsset.id, cveId, { status, review_note: reviewNote }, csrfToken);
    setExposures((current) => current.map((item) => item.cve_id === cveId ? updated : item));
    setNotice(`Review ${cveId} disimpan.`);
  }

  function closeExposures() {
    setExposureAsset(null);
    setExposures([]);
    setExposuresError("");
    if (currentViewHash() === "assets") {
      window.location.hash = "/assets";
    }
  }

  return (
    <>
      <section className="asset-page">
        <div className="asset-toolbar">
          <label className="search-control">
            <Search size={17} />
            <input aria-label="Cari asset" autoComplete="off" name="asset_query" onChange={(event) => setQuery(event.target.value)} placeholder="Cari asset…" value={query} />
          </label>
          <span className="result-count">{filteredAssets.length} asset</span>
          <button className="secondary-asset-button refresh-button" disabled={busy} onClick={() => void recalculateExposures()} type="button">
            <RefreshCw size={17} />Hitung ulang paparan
          </button>
          <button className="add-asset-button" onClick={openCreate} type="button">
            <Plus size={17} />Tambah aset
          </button>
        </div>
        {pageError && <div className="form-error" role="alert">{pageError}</div>}
        {notice && <div className="form-success" role="status">{notice}</div>}
        <Panel title="Aset terpantau" icon={<Server size={18} />} wide>
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th>Aset</th><th>Jenis</th><th>Produk</th><th>Konteks</th><th>Pemilik</th><th>CVE terkait</th><th>Risiko</th><th aria-label="Aksi" /></tr>
              </thead>
              <tbody>
                {!loading && filteredAssets.map((asset) => (
                  <tr key={asset.id}>
                    <td><strong>{asset.name}</strong></td>
                    <td>{asset.asset_type}</td>
                    <td>
                      <div className="asset-product-cell">
                        <strong>{[asset.vendor, asset.product].filter(Boolean).join(" ") || asset.os_version || "-"}</strong>
                        <span>{asset.version || asset.os_version || "Versi tidak diketahui"}</span>
                      </div>
                    </td>
                    <td>
                      <div className="asset-product-cell">
                        <strong>{asset.environment || "Belum ditentukan"}</strong>
                        <span>Kritikalitas {asset.criticality}{asset.internet_exposed ? " · Terpapar internet" : ""}</span>
                      </div>
                    </td>
                    <td>{asset.owner || "-"}</td>
                    <td>
                      <button
                        className="asset-exposure-link"
                        disabled={asset.matching_cve === 0}
                        onClick={() => void openExposures(asset)}
                        title={asset.matching_cve ? `Lihat ${asset.matching_cve} CVE terkait` : "Tidak ada CVE terkait"}
                        type="button"
                      >
                        {asset.matching_cve}
                      </button>
                    </td>
                    <td><span className={severityClass(asset.risk)}>{asset.risk}</span></td>
                    <td className="asset-row-actions">
                      <button aria-label={`Edit ${asset.name}`} onClick={() => openEdit(asset)} title={`Edit ${asset.name}`} type="button"><Pencil size={15} /></button>
                      <button
                        aria-label={`Hapus ${asset.name}`}
                        className="danger"
                        onClick={() => {
                          setModalError("");
                          setNotice("");
                          setDeletingAsset(asset);
                        }}
                        title={`Hapus ${asset.name}`}
                        type="button"
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
                {loading && <tr><td className="table-state" colSpan={8}>Memuat asset…</td></tr>}
                {!loading && filteredAssets.length === 0 && <tr><td className="table-state" colSpan={8}>Asset tidak ditemukan.</td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>
      </section>

      {editingAsset !== undefined && (
        <AssetFormModal
          asset={editingAsset}
          busy={busy}
          error={modalError}
          onClose={() => !busy && setEditingAsset(undefined)}
          onSubmit={(payload) => void saveAsset(payload)}
        />
      )}
      {deletingAsset && (
        <DeleteAssetModal
          asset={deletingAsset}
          busy={busy}
          error={modalError}
          onClose={() => !busy && setDeletingAsset(null)}
          onConfirm={() => void removeAsset()}
        />
      )}
      {exposureAsset && (
        <AssetExposureDrawer
          asset={exposureAsset}
          error={exposuresError}
          exposures={exposures}
          loading={exposuresLoading}
          onClose={closeExposures}
          onReviewUpdate={updateExposureReview}
        />
      )}
    </>
  );
}
