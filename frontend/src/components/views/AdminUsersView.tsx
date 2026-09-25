import { AlertTriangle, MonitorX, RefreshCw, ShieldCheck, Trash2, UserPlus, Users, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createUser, deleteUser, fetchSessions, fetchUsers, revokeSession, type User, type UserRole, type UserSession } from "../../lib/auth";
import { formatApiDate, formatApiDateTime } from "../../lib/datetime";
import { analyzePassword, PASSWORD_MIN_LENGTH } from "../../lib/password";
import { PasswordStrength } from "../auth/PasswordStrength";
import { Panel } from "../ui/Panel";
import { useDialogFocus } from "../../hooks/useDialogFocus";

type Props = {
  csrfToken: string;
  currentUserId: number;
};

export function AdminUsersView({ csrfToken, currentUserId }: Props) {
  const [users, setUsers] = useState<User[]>([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("user");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busy, setBusy] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<User | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState<number | null>(null);
  const deleteDialogRef = useRef<HTMLDivElement>(null);
  useDialogFocus(deleteDialogRef, {
    closeDisabled: deletingId !== null || pendingDelete === null,
    onClose: () => setPendingDelete(null),
  });

  async function loadUsers() {
    try {
      setUsers(await fetchUsers());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal memuat user.");
    }
  }

  async function loadSessions() {
    setSessionsLoading(true);
    try {
      setSessions(await fetchSessions());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal memuat session.");
    } finally {
      setSessionsLoading(false);
    }
  }

  useEffect(() => {
    void loadUsers();
    void loadSessions();
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (!analyzePassword(password).valid) {
      setError("Password belum memenuhi seluruh policy.");
      return;
    }
    setBusy(true);
    try {
      const created = await createUser(username, password, role, csrfToken);
      setUsers((current) => [...current, created]);
      setUsername("");
      setPassword("");
      setRole("user");
      setSuccess(`User ${created.username} berhasil dibuat.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal membuat user.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(session: UserSession) {
    setError("");
    setSuccess("");
    setRevokingSessionId(session.id);
    try {
      await revokeSession(session.id, csrfToken);
      setSessions((current) => current.filter((item) => item.id !== session.id));
      setSuccess(`Session ${session.username} berhasil dicabut.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal mencabut session.");
    } finally {
      setRevokingSessionId(null);
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setError("");
    setSuccess("");
    setDeletingId(pendingDelete.id);
    try {
      await deleteUser(pendingDelete.id, csrfToken);
      setUsers((current) => current.filter((user) => user.id !== pendingDelete.id));
      setSuccess(`User ${pendingDelete.username} berhasil dihapus.`);
      setPendingDelete(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Gagal menghapus user.");
    } finally {
      setDeletingId(null);
    }
  }

  const adminCount = users.filter((user) => user.role === "admin").length;

  return (
    <>
      <section className="users-layout">
        <Panel className="create-user-panel" title="Create User" icon={<UserPlus size={18} />}>
          <form className="admin-user-form" onSubmit={submit}>
            <label>Username<input autoComplete="off" minLength={3} name="username" onChange={(event) => setUsername(event.target.value)} required spellCheck={false} value={username} /></label>
            <label>Password<input autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} name="password" onChange={(event) => setPassword(event.target.value)} required type="password" value={password} /></label>
            <PasswordStrength password={password} />
            <label>Permission
              <select name="role" onChange={(event) => setRole(event.target.value as UserRole)} value={role}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </label>
            {error && <div className="form-error" role="alert">{error}</div>}
            {success && <div className="form-success" role="status">{success}</div>}
            <button disabled={busy || !analyzePassword(password).valid} type="submit"><UserPlus size={18} />{busy ? "Membuat…" : "Buat user"}</button>
          </form>
        </Panel>

        <Panel className="user-list-panel" title="Users" icon={<Users size={18} />}>
          <div className="table-scroll">
            <table>
              <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Dibuat</th><th aria-label="Actions" /></tr></thead>
              <tbody>
                {users.map((user) => {
                  const isSelf = user.id === currentUserId;
                  const isLastAdmin = user.role === "admin" && adminCount === 1;
                  const deleteDisabled = isSelf || isLastAdmin;
                  const deleteTitle = isSelf
                    ? "Akun yang sedang dipakai tidak dapat dihapus"
                    : isLastAdmin
                      ? "Admin terakhir tidak dapat dihapus"
                      : `Hapus ${user.username}`;
                  return (
                    <tr key={user.id}>
                      <td>{user.username}{isSelf && <span className="self-label">You</span>}</td>
                      <td><span className={`role-badge role-${user.role}`}><ShieldCheck size={13} />{user.role}</span></td>
                      <td>{user.active ? "Active" : "Disabled"}</td>
                      <td>{formatApiDate(user.created_at)}</td>
                      <td className="user-actions">
                        <button
                          aria-label={deleteTitle}
                          className="delete-user-button"
                          disabled={deleteDisabled}
                          onClick={() => setPendingDelete(user)}
                          title={deleteTitle}
                          type="button"
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel
          className="user-sessions-panel"
          title="Active sessions"
          icon={<MonitorX size={18} />}
          action={<button className="button-secondary refresh-button" disabled={sessionsLoading} onClick={() => void loadSessions()} type="button"><RefreshCw className={sessionsLoading ? "loading-spinner" : ""} size={15} />Muat ulang</button>}
        >
          <div className="table-scroll user-sessions-scroll">
            <table>
              <thead><tr><th>User</th><th>IP</th><th>Device</th><th>Last seen</th><th>Expires</th><th aria-label="Actions" /></tr></thead>
              <tbody>
                {sessions.map((session) => (
                  <tr key={session.id}>
                    <td>{session.username}{session.current && <span className="self-label">Current</span>}</td>
                    <td>{session.ip_address || "-"}</td>
                    <td className="source-message-cell">{session.user_agent || "-"}</td>
                    <td>{formatApiDateTime(session.last_seen_at, { dateStyle: "medium", timeStyle: "short" })}</td>
                    <td>{formatApiDateTime(session.expires_at, { dateStyle: "medium", timeStyle: "short" })}</td>
                    <td className="user-actions">
                      <button
                        aria-label={`Revoke session ${session.username}`}
                        className="delete-user-button"
                        disabled={session.current || revokingSessionId === session.id}
                        onClick={() => void revoke(session)}
                        title={session.current ? "Session saat ini tidak bisa dicabut dari sini" : "Revoke session"}
                        type="button"
                      >
                        <MonitorX size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
                {sessionsLoading && sessions.length === 0 && <tr><td className="table-state" colSpan={6}>Memuat session…</td></tr>}
                {!sessionsLoading && sessions.length === 0 && <tr><td className="table-state" colSpan={6}>Tidak ada session aktif.</td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>
      </section>

      {pendingDelete && (
        <div className="modal-backdrop" onMouseDown={() => deletingId === null && setPendingDelete(null)}>
          <div
            aria-labelledby="delete-user-title"
            aria-modal="true"
            className="confirm-modal"
            onMouseDown={(event) => event.stopPropagation()}
            ref={deleteDialogRef}
            role="dialog"
          >
            <button aria-label="Tutup" className="modal-close" disabled={deletingId !== null} onClick={() => setPendingDelete(null)} type="button">
              <X size={18} />
            </button>
            <div className="confirm-icon"><AlertTriangle size={22} /></div>
            <h2 id="delete-user-title">Hapus user?</h2>
            <p>Akun <strong>{pendingDelete.username}</strong> dan seluruh sesi loginnya akan dihapus permanen.</p>
            <div className="modal-actions">
              <button className="button-secondary" disabled={deletingId !== null} onClick={() => setPendingDelete(null)} type="button">Batal</button>
              <button className="button-danger" disabled={deletingId !== null} onClick={() => void confirmDelete()} type="button">
                <Trash2 size={16} />{deletingId !== null ? "Menghapus…" : "Hapus"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
