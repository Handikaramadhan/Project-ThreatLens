import { useEffect, useState } from "react";
import type { User } from "../lib/auth";
import type { DashboardPayload } from "../lib/api";
import { Sidebar } from "./layout/Sidebar";
import { Topbar } from "./layout/Topbar";
import { currentView, type ViewKey, viewMeta } from "./types";
import { AlertsView } from "./views/AlertsView";
import { AssetsView } from "./views/AssetsView";
import { CveView } from "./views/CveView";
import { DashboardView } from "./views/DashboardView";
import { IocView } from "./views/IocView";
import { ReportsView } from "./views/ReportsView";
import { ThreatFeedView } from "./views/ThreatFeedView";
import { AdminUsersView } from "./views/AdminUsersView";
import { AIThreatIntelView } from "./views/AIThreatIntelView";

type Props = {
  data: DashboardPayload;
  apiStatus: "live" | "fallback";
  csrfToken: string;
  currentUser: User;
  onDataRefresh: () => void;
  onLogout: () => void;
};

export function Dashboard({ data, apiStatus, csrfToken, currentUser, onDataRefresh, onLogout }: Props) {
  const [activeView, setActiveView] = useState<ViewKey>(currentView);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const savedPreference = window.localStorage.getItem("threatlens-sidebar-collapsed");
    return savedPreference === null
      ? window.matchMedia("(max-width: 840px)").matches
      : savedPreference === "true";
  });

  useEffect(() => {
    const handleHashChange = () => setActiveView(currentView());
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  useEffect(() => {
    if (activeView === "users" && currentUser.role !== "admin") {
      navigate("dashboard");
    }
  }, [activeView, currentUser.role]);

  useEffect(() => {
    window.localStorage.setItem("threatlens-sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  function navigate(view: ViewKey) {
    setActiveView(view);
    window.location.hash = `/${view}`;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  const meta = viewMeta[activeView];

  return (
    <div className={sidebarCollapsed ? "app-shell sidebar-collapsed" : "app-shell"}>
      <Sidebar
        activeView={activeView}
        collapsed={sidebarCollapsed}
        isAdmin={currentUser.role === "admin"}
        onNavigate={navigate}
        onToggle={() => setSidebarCollapsed((value) => !value)}
      />
      <main className="main">
        <Topbar apiStatus={apiStatus} eyebrow={meta.eyebrow} onLogout={onLogout} title={meta.title} user={currentUser} />
        {activeView === "dashboard" && <DashboardView data={data} />}
        {activeView === "ai" && <AIThreatIntelView csrfToken={csrfToken} />}
        {activeView === "cve" && <CveView csrfToken={csrfToken} cves={data.cves} />}
        {activeView === "feed" && <ThreatFeedView news={data.news} />}
        {activeView === "ioc" && <IocView iocs={data.iocs} />}
        {activeView === "assets" && <AssetsView csrfToken={csrfToken} onAssetsChanged={onDataRefresh} />}
        {activeView === "alerts" && <AlertsView />}
        {activeView === "reports" && <ReportsView data={data} />}
        {activeView === "users" && currentUser.role === "admin" && (
          <AdminUsersView csrfToken={csrfToken} currentUserId={currentUser.id} />
        )}
      </main>
    </div>
  );
}
