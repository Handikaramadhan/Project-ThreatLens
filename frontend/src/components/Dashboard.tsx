import { RefreshCw } from "lucide-react";
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
import { SourceHealthView } from "./views/SourceHealthView";
import { ThreatFeedView } from "./views/ThreatFeedView";
import { AdminAuditView } from "./views/AdminAuditView";
import { AdminSystemHealthView } from "./views/AdminSystemHealthView";
import { AdminUsersView } from "./views/AdminUsersView";
import { AIThreatIntelView } from "./views/AIThreatIntelView";

type Props = {
  data: DashboardPayload;
  apiStatus: "loading" | "live" | "unavailable";
  csrfToken: string;
  currentUser: User;
  onDataRefresh: () => void;
  onLogout: () => void;
};

export function Dashboard({ data, apiStatus, csrfToken, currentUser, onDataRefresh, onLogout }: Props) {
  const [activeView, setActiveView] = useState<ViewKey>(currentView);
  const [isMobile, setIsMobile] = useState(() => window.matchMedia("(max-width: 840px)").matches);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (window.matchMedia("(max-width: 840px)").matches) return true;
    const savedPreference = window.localStorage.getItem("threatlens-sidebar-collapsed");
    return savedPreference === "true";
  });

  useEffect(() => {
    const handleHashChange = () => setActiveView(currentView());
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  useEffect(() => {
    if (["users", "audit", "system"].includes(activeView) && currentUser.role !== "admin") {
      navigate("dashboard");
    }
  }, [activeView, currentUser.role]);

  useEffect(() => {
    if (activeView === "sources") {
      onDataRefresh();
    }
  }, [activeView]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 840px)");
    const handleViewportChange = () => {
      setIsMobile(media.matches);
      setSidebarCollapsed(media.matches ? true : window.localStorage.getItem("threatlens-sidebar-collapsed") === "true");
    };
    media.addEventListener("change", handleViewportChange);
    return () => media.removeEventListener("change", handleViewportChange);
  }, []);

  useEffect(() => {
    if (!isMobile) window.localStorage.setItem("threatlens-sidebar-collapsed", String(sidebarCollapsed));
  }, [isMobile, sidebarCollapsed]);

  function navigate(view: ViewKey) {
    setActiveView(view);
    if (isMobile) setSidebarCollapsed(true);
    window.location.hash = `/${view}`;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  const meta = viewMeta[activeView];

  return (
    <div className={sidebarCollapsed ? "app-shell sidebar-collapsed" : "app-shell"}>
      <a className="skip-link" href="#main-content" onClick={(event) => {
        event.preventDefault();
        document.getElementById("main-content")?.focus();
      }}>Lewati ke konten utama</a>
      <Sidebar
        activeView={activeView}
        collapsed={sidebarCollapsed}
        isAdmin={currentUser.role === "admin"}
        isMobile={isMobile}
        onNavigate={navigate}
        onToggle={() => setSidebarCollapsed((value) => !value)}
      />
      <main className="main" id="main-content" tabIndex={-1}>
        <Topbar
          apiStatus={apiStatus}
          eyebrow={meta.eyebrow}
          onAlerts={() => navigate("alerts")}
          onLogout={onLogout}
          title={meta.title}
          user={currentUser}
        />
        {apiStatus === "unavailable" && (
          <div className="api-unavailable" role="alert">
            <span>Data terbaru tidak dapat dimuat. Periksa koneksi atau coba lagi.</span>
            <button className="button-secondary refresh-button" onClick={onDataRefresh} type="button"><RefreshCw size={15} />Coba lagi</button>
          </div>
        )}
        {activeView === "dashboard" && <DashboardView data={data} />}
        {activeView === "ai" && <AIThreatIntelView csrfToken={csrfToken} />}
        {activeView === "cve" && <CveView csrfToken={csrfToken} cves={data.cves} />}
        {activeView === "feed" && <ThreatFeedView news={data.news} />}
        {activeView === "ioc" && <IocView iocs={data.iocs} />}
        {activeView === "sources" && <SourceHealthView collection={data.collection} />}
        {activeView === "assets" && <AssetsView csrfToken={csrfToken} onAssetsChanged={onDataRefresh} />}
        {activeView === "alerts" && <AlertsView csrfToken={csrfToken} />}
        {activeView === "reports" && <ReportsView data={data} />}
        {activeView === "users" && currentUser.role === "admin" && (
          <AdminUsersView csrfToken={csrfToken} currentUserId={currentUser.id} />
        )}
        {activeView === "audit" && currentUser.role === "admin" && <AdminAuditView />}
        {activeView === "system" && currentUser.role === "admin" && <AdminSystemHealthView />}
      </main>
    </div>
  );
}
