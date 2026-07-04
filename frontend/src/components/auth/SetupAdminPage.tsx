import { UserPlus } from "lucide-react";
import { useState } from "react";
import { bootstrapAdmin } from "../../lib/auth";
import { analyzePassword, PASSWORD_MIN_LENGTH } from "../../lib/password";
import { AuthLayout } from "./AuthLayout";
import { PasswordStrength } from "./PasswordStrength";

export function SetupAdminPage({ onComplete }: { onComplete: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    if (!analyzePassword(password).valid) {
      setError("Password belum memenuhi seluruh policy.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Konfirmasi password tidak sama.");
      return;
    }
    setBusy(true);
    try {
      await bootstrapAdmin(username, password);
      onComplete();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Setup gagal.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout eyebrow="First-run setup" title="Buat admin pertama">
      <form className="auth-form" onSubmit={submit}>
        <label>Username<input autoComplete="username" minLength={3} onChange={(event) => setUsername(event.target.value)} required value={username} /></label>
        <label>Password<input autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} onChange={(event) => setPassword(event.target.value)} required type="password" value={password} /></label>
        <PasswordStrength password={password} />
        <label>Konfirmasi password<input autoComplete="new-password" minLength={PASSWORD_MIN_LENGTH} onChange={(event) => setConfirmPassword(event.target.value)} required type="password" value={confirmPassword} /></label>
        {error && <div className="form-error" role="alert">{error}</div>}
        <button disabled={busy || !analyzePassword(password).valid} type="submit"><UserPlus size={18} />{busy ? "Membuat..." : "Buat admin"}</button>
      </form>
    </AuthLayout>
  );
}
