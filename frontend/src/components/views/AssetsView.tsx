import { Pencil, Plus, Search, Server, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  createAsset,
  deleteAsset,
  fetchAssets,
  updateAsset,
  type Asset,
  type AssetInput,
} from "../../lib/assets";
import { AssetFormModal } from "../assets/AssetFormModal";
import { DeleteAssetModal } from "../assets/DeleteAssetModal";
import { severityClass } from "../ui/CveTable";
import { Panel } from "../ui/Panel";

type Props = {
  csrfToken: string;
  onAssetsChanged: () => void;
};

export function AssetsView({ csrfToken, onAssetsChanged }: Props) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState("");
  const [notice, setNotice] = useState("");
  const [editingAsset, setEditingAsset] = useState<Asset | null | undefined>(undefined);
  const [deletingAsset, setDeletingAsset] = useState<Asset | null>(null);
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

  const filteredAssets = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return assets;
    return assets.filter((asset) =>
      [asset.name, asset.asset_type, asset.os_version, asset.owner, asset.risk]
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

  return (
    <>
      <section className="asset-page">
        <div className="asset-toolbar">
          <label className="search-control">
            <Search size={17} />
            <input aria-label="Cari asset" onChange={(event) => setQuery(event.target.value)} placeholder="Cari asset..." value={query} />
          </label>
          <span className="result-count">{filteredAssets.length} asset</span>
          <button className="add-asset-button" onClick={openCreate} type="button">
            <Plus size={17} />Tambah asset
          </button>
        </div>
        {pageError && <div className="form-error" role="alert">{pageError}</div>}
        {notice && <div className="form-success" role="status">{notice}</div>}
        <Panel title="Monitored Assets" icon={<Server size={18} />} wide>
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th>Asset</th><th>Type</th><th>OS/Version</th><th>Owner</th><th>Matching CVE</th><th>Risk</th><th aria-label="Actions" /></tr>
              </thead>
              <tbody>
                {!loading && filteredAssets.map((asset) => (
                  <tr key={asset.id}>
                    <td><strong>{asset.name}</strong></td>
                    <td>{asset.asset_type}</td>
                    <td>{asset.os_version || "-"}</td>
                    <td>{asset.owner || "-"}</td>
                    <td>{asset.matching_cve}</td>
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
                {loading && <tr><td className="table-state" colSpan={7}>Memuat asset...</td></tr>}
                {!loading && filteredAssets.length === 0 && <tr><td className="table-state" colSpan={7}>Asset tidak ditemukan.</td></tr>}
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
    </>
  );
}
