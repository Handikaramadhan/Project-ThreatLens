import { HardDrive, Save, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { Asset, AssetInput, AssetRisk } from "../../lib/assets";
import { useDialogFocus } from "../../hooks/useDialogFocus";

type Props = {
  asset: Asset | null;
  busy: boolean;
  error: string;
  onClose: () => void;
  onSubmit: (payload: AssetInput) => void;
};

const emptyAsset: AssetInput = {
  name: "",
  asset_type: "",
  os_version: "",
  vendor: "",
  product: "",
  version: "",
  environment: "",
  criticality: "Medium",
  internet_exposed: false,
  owner: "",
  risk: "Low",
};

export function AssetFormModal({ asset, busy, error, onClose, onSubmit }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useDialogFocus(dialogRef, { closeDisabled: busy, onClose });
  const [form, setForm] = useState<AssetInput>(
    asset
      ? {
          name: asset.name,
          asset_type: asset.asset_type,
          os_version: asset.os_version,
          vendor: asset.vendor,
          product: asset.product,
          version: asset.version,
          environment: asset.environment,
          criticality: asset.criticality,
          internet_exposed: asset.internet_exposed,
          owner: asset.owner,
          risk: asset.risk,
        }
      : emptyAsset
  );

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [busy, onClose]);

  function setField<K extends keyof AssetInput>(field: K, value: AssetInput[K]) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  return (
    <div className="modal-backdrop" onMouseDown={() => !busy && onClose()}>
      <div
        aria-labelledby="asset-form-title"
        aria-modal="true"
        className="asset-modal"
        onMouseDown={(event) => event.stopPropagation()}
        ref={dialogRef}
        role="dialog"
      >
        <button aria-label="Tutup" className="modal-close" disabled={busy} onClick={onClose} type="button">
          <X size={18} />
        </button>
        <div className="asset-modal-heading">
          <span><HardDrive size={19} /></span>
          <div>
            <h2 id="asset-form-title">{asset ? "Edit asset" : "Tambah asset"}</h2>
            <p>{asset ? asset.name : "Monitored asset baru"}</p>
          </div>
        </div>
        <form
          className="asset-form"
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit(form);
          }}
        >
          <label>
            Asset name / hostname
            <input autoComplete="off" data-autofocus maxLength={120} minLength={2} name="asset_name" onChange={(event) => setField("name", event.target.value)} required value={form.name} />
          </label>
          <label>
            Type
            <input autoComplete="off" list="asset-types" maxLength={80} minLength={2} name="asset_type" onChange={(event) => setField("asset_type", event.target.value)} required value={form.asset_type} />
            <datalist id="asset-types">
              <option value="Server" />
              <option value="Workstation" />
              <option value="Firewall" />
              <option value="Network Device" />
              <option value="Hypervisor" />
              <option value="Container Host" />
              <option value="Database" />
              <option value="Application" />
              <option value="Cloud Resource" />
            </datalist>
          </label>
          <label>
            OS / Version
            <input autoComplete="off" maxLength={120} name="os_version" onChange={(event) => setField("os_version", event.target.value)} value={form.os_version} />
          </label>
          <div className="asset-form-section">
            <span>Matching metadata</span>
            <p>Isi vendor/product/version kalau diketahui. Ini dipakai untuk menaikkan confidence dan mengurangi false positive.</p>
          </div>
          <label>
            Vendor
            <input autoComplete="off" maxLength={120} name="vendor" onChange={(event) => setField("vendor", event.target.value)} placeholder="Contoh: Red Hat, Microsoft, F5…" value={form.vendor} />
          </label>
          <label>
            Product
            <input autoComplete="off" maxLength={120} name="product" onChange={(event) => setField("product", event.target.value)} placeholder="Contoh: Enterprise Linux, Exchange Server, nginx…" value={form.product} />
          </label>
          <label>
            Product version
            <input autoComplete="off" maxLength={80} name="version" onChange={(event) => setField("version", event.target.value)} placeholder="Contoh: 9.8, 2019, 1.24.0…" value={form.version} />
          </label>
          <label>
            Environment
            <input autoComplete="off" list="asset-environments" maxLength={40} name="environment" onChange={(event) => setField("environment", event.target.value)} placeholder="Production, staging, lab…" value={form.environment} />
            <datalist id="asset-environments">
              <option value="Production" />
              <option value="Staging" />
              <option value="Development" />
              <option value="Lab" />
              <option value="DR" />
            </datalist>
          </label>
          <label>
            Owner
            <input autoComplete="off" maxLength={120} name="owner" onChange={(event) => setField("owner", event.target.value)} value={form.owner} />
          </label>
          <label>
            Criticality
            <select name="criticality" onChange={(event) => setField("criticality", event.target.value as AssetRisk)} value={form.criticality}>
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Critical">Critical</option>
            </select>
          </label>
          <label>
            Risk
            <select name="risk" onChange={(event) => setField("risk", event.target.value as AssetRisk)} value={form.risk}>
              <option value="Low">Low</option>
              <option value="Medium">Medium</option>
              <option value="High">High</option>
              <option value="Critical">Critical</option>
            </select>
          </label>
          <label className="asset-checkbox">
            <input checked={form.internet_exposed} name="internet_exposed" onChange={(event) => setField("internet_exposed", event.target.checked)} type="checkbox" />
            Internet exposed
          </label>
          {error && <div className="form-error asset-form-message" role="alert">{error}</div>}
          <div className="modal-actions asset-form-actions">
            <button className="button-secondary" disabled={busy} onClick={onClose} type="button">Batal</button>
            <button className="button-primary" disabled={busy} type="submit">
              <Save size={16} />{busy ? "Menyimpan…" : "Simpan"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
