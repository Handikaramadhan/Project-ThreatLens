import { LogIn } from "lucide-react";
import { useState } from "react";
import { login, type AuthSession } from "../../lib/auth";
import { AuthLayout } from "./AuthLayout";

export function LoginPage({ onLogin }: { onLogin: (session: AuthSession) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      onLogin(await login(username, password));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Login gagal.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout eyebrow="Secure access" title="Masuk ke ThreatLens">
      <form className="auth-form" onSubmit={submit}>
        <label>Username<input autoComplete="username" onChange={(event) => setUsername(event.target.value)} required value={username} /></label>
        <label>Password<input autoComplete="current-password" onChange={(event) => setPassword(event.target.value)} required type="password" value={password} /></label>
        {error && <div className="form-error" role="alert">{error}</div>}
        <button disabled={busy} type="submit"><LogIn size={18} />{busy ? "Memeriksa..." : "Login"}</button>
      </form>
    </AuthLayout>
  );
}
