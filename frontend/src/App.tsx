import { useEffect, useRef, useState } from "react";
import { Dashboard } from "./components/Dashboard";
import { AuthLayout } from "./components/auth/AuthLayout";
import { LoginPage } from "./components/auth/LoginPage";
import { SetupAdminPage } from "./components/auth/SetupAdminPage";
import { AuthHttpError, fetchAuthStatus, fetchCurrentSession, logout, type AuthSession } from "./lib/auth";
import { emptyDashboard, fetchDashboard, type DashboardPayload } from "./lib/api";

type Stage = "loading" | "setup" | "login" | "app" | "unavailable";

export function App() {
  const [stage, setStage] = useState<Stage>("loading");
  const [session, setSession] = useState<AuthSession | null>(null);
  const [data, setData] = useState<DashboardPayload>(emptyDashboard);
  const [apiStatus, setApiStatus] = useState<"loading" | "live" | "unavailable">("loading");
  const dashboardRequestId = useRef(0);

  async function initialize() {
    setStage("loading");
    try {
      const status = await fetchAuthStatus();
      if (!status.initialized) {
        setStage("setup");
        return;
      }
      try {
        const current = await fetchCurrentSession();
        setSession(current);
        setStage("app");
      } catch (reason) {
        setStage(reason instanceof AuthHttpError && reason.status === 401 ? "login" : "unavailable");
      }
    } catch {
      setStage("unavailable");
    }
  }

  useEffect(() => {
    void initialize();
  }, []);

  useEffect(() => {
    if (stage !== "app") {
      return;
    }
    void refreshDashboard();
  }, [stage]);

  async function refreshDashboard() {
    const currentRequest = ++dashboardRequestId.current;
    setApiStatus("loading");
    await fetchDashboard()
      .then((payload) => {
        if (currentRequest !== dashboardRequestId.current) return;
        setData(payload);
        setApiStatus("live");
      })
      .catch(() => {
        if (currentRequest !== dashboardRequestId.current) return;
        setApiStatus("unavailable");
      });
  }

  useEffect(() => {
    if (stage !== "app") {
      return;
    }
    const timer = window.setInterval(() => {
      fetchCurrentSession()
        .then(setSession)
        .catch((reason) => {
          setApiStatus("unavailable");
          if (reason instanceof AuthHttpError && reason.status === 401) {
            setSession(null);
            setStage("login");
          }
        });
    }, 5 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, [stage]);

  async function handleLogout() {
    if (session) {
      await logout(session.csrf_token).catch(() => undefined);
    }
    setSession(null);
    setApiStatus("loading");
    setStage("login");
  }

  if (stage === "loading") {
    return <main className="auth-page"><div className="auth-loading" role="status">Memuat ThreatLens…</div></main>;
  }
  if (stage === "unavailable") {
    return (
      <AuthLayout eyebrow="Connection" title="ThreatLens belum tersedia">
        <div className="auth-form">
          <div className="form-error" role="alert">Tidak dapat terhubung ke server. Periksa koneksi dan coba lagi.</div>
          <button onClick={() => void initialize()} type="button">Coba lagi</button>
        </div>
      </AuthLayout>
    );
  }
  if (stage === "setup") {
    return <SetupAdminPage onComplete={() => setStage("login")} />;
  }
  if (stage === "login" || session === null) {
    return <LoginPage onLogin={(nextSession) => { setSession(nextSession); setApiStatus("loading"); setStage("app"); }} />;
  }
  return (
    <Dashboard
      apiStatus={apiStatus}
      csrfToken={session.csrf_token}
      currentUser={session.user}
      data={data}
      onDataRefresh={() => void refreshDashboard()}
      onLogout={handleLogout}
    />
  );
}
