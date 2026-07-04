import { useEffect, useState } from "react";
import { Dashboard } from "./components/Dashboard";
import { LoginPage } from "./components/auth/LoginPage";
import { SetupAdminPage } from "./components/auth/SetupAdminPage";
import { fetchAuthStatus, fetchCurrentSession, logout, type AuthSession } from "./lib/auth";
import { fallbackDashboard, fetchDashboard, type DashboardPayload } from "./lib/api";

type Stage = "loading" | "setup" | "login" | "app";

export function App() {
  const [stage, setStage] = useState<Stage>("loading");
  const [session, setSession] = useState<AuthSession | null>(null);
  const [data, setData] = useState<DashboardPayload>(fallbackDashboard);
  const [apiStatus, setApiStatus] = useState<"live" | "fallback">("fallback");

  useEffect(() => {
    async function initialize() {
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
        } catch {
          setStage("login");
        }
      } catch {
        setStage("login");
      }
    }
    void initialize();
  }, []);

  useEffect(() => {
    if (stage !== "app") {
      return;
    }
    void refreshDashboard();
  }, [stage]);

  async function refreshDashboard() {
    await fetchDashboard()
      .then((payload) => {
        setData(payload);
        setApiStatus("live");
      })
      .catch(() => {
        setData(fallbackDashboard);
        setApiStatus("fallback");
      });
  }

  useEffect(() => {
    if (stage !== "app") {
      return;
    }
    const timer = window.setInterval(() => {
      fetchCurrentSession()
        .then(setSession)
        .catch(() => {
          setSession(null);
          setApiStatus("fallback");
          setStage("login");
        });
    }, 5 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, [stage]);

  async function handleLogout() {
    if (session) {
      await logout(session.csrf_token).catch(() => undefined);
    }
    setSession(null);
    setApiStatus("fallback");
    setStage("login");
  }

  if (stage === "loading") {
    return <main className="auth-page"><div className="auth-loading">Memuat ThreatLens...</div></main>;
  }
  if (stage === "setup") {
    return <SetupAdminPage onComplete={() => setStage("login")} />;
  }
  if (stage === "login" || session === null) {
    return <LoginPage onLogin={(nextSession) => { setSession(nextSession); setStage("app"); }} />;
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
