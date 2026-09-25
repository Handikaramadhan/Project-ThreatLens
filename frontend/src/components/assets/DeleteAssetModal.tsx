import { AlertTriangle, Trash2, X } from "lucide-react";
import { useRef } from "react";
import type { Asset } from "../../lib/assets";
import { useDialogFocus } from "../../hooks/useDialogFocus";

type Props = {
  asset: Asset;
  busy: boolean;
  error: string;
  onClose: () => void;
  onConfirm: () => void;
};

export function DeleteAssetModal({ asset, busy, error, onClose, onConfirm }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useDialogFocus(dialogRef, { closeDisabled: busy, onClose });

  return (
    <div className="modal-backdrop" onMouseDown={() => !busy && onClose()}>
      <div
        aria-labelledby="delete-asset-title"
        aria-modal="true"
        className="confirm-modal"
        onMouseDown={(event) => event.stopPropagation()}
        ref={dialogRef}
        role="dialog"
      >
        <button aria-label="Tutup" className="modal-close" disabled={busy} onClick={onClose} type="button">
          <X size={18} />
        </button>
        <div className="confirm-icon"><AlertTriangle size={22} /></div>
        <h2 id="delete-asset-title">Hapus asset?</h2>
        <p>Asset <strong>{asset.name}</strong> dan data exposure terkait akan dihapus permanen.</p>
        {error && <div className="form-error modal-error" role="alert">{error}</div>}
        <div className="modal-actions">
          <button className="button-secondary" disabled={busy} onClick={onClose} type="button">Batal</button>
          <button className="button-danger" disabled={busy} onClick={onConfirm} type="button">
            <Trash2 size={16} />{busy ? "Menghapus…" : "Hapus"}
          </button>
        </div>
      </div>
    </div>
  );
}
