import {
  Bell,
  Boxes,
  FileText,
  History,
  LayoutDashboard,
  Menu,
  Radar,
  RadioTower,
  Search,
  Server,
  Settings2,
  Shield,
  Sparkles,
  Users,
  X
} from "lucide-react";
import { BrandLockup } from "../brand/BrandLockup";
import type { ViewKey } from "../types";

const navGroups = [
  {
    label: "Workspace",
    items: [["Ringkasan", LayoutDashboard, "dashboard"]]
  },
  {
    label: "Intelijen",
    items: [
      ["AI Intel", Sparkles, "ai"],
      ["Kerentanan", Shield, "cve"],
      ["Threat feed", Radar, "feed"],
      ["Indikator", Search, "ioc"]
    ]
  },
  {
    label: "Operasional",
    items: [
      ["Sumber", RadioTower, "sources"],
      ["Aset", Server, "assets"],
      ["Peringatan", Bell, "alerts"],
      ["Laporan", FileText, "reports"]
    ]
  }
] as const;

type Props = {
  activeView: ViewKey;
  collapsed: boolean;
  isAdmin: boolean;
  isMobile: boolean;
  onNavigate: (view: ViewKey) => void;
  onToggle: () => void;
};

export function Sidebar({ activeView, collapsed, isAdmin, isMobile, onNavigate, onToggle }: Props) {
  return (
    <aside className={collapsed ? "sidebar collapsed" : "sidebar"}>
      <div className="brand">
        <button
          aria-controls={isMobile ? "primary-navigation" : undefined}
          aria-expanded={isMobile ? !collapsed : undefined}
          aria-label={collapsed ? "Tampilkan menu" : "Sembunyikan menu"}
          className="brand-toggle"
          onClick={onToggle}
          title={collapsed ? "Tampilkan menu" : "Sembunyikan menu"}
          type="button"
        >
          <BrandLockup compact={collapsed} />
          {collapsed ? <Menu aria-hidden="true" className="mobile-menu-icon" size={20} /> : <X aria-hidden="true" className="mobile-menu-icon" size={20} />}
        </button>
      </div>

      <nav aria-label="Navigasi utama" id="primary-navigation">
        {navGroups.map((group) => (
          <div className="nav-group" key={group.label}>
            <span className="nav-group-label">{group.label}</span>
            {group.items.map(([label, Icon, view]) => (
              <a
                aria-label={label}
                aria-current={activeView === view ? "page" : undefined}
                className={activeView === view ? "active" : ""}
                href={`#/${view}`}
                key={view}
                onClick={(event) => {
                  if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) onNavigate(view);
                }}
                title={collapsed ? label : undefined}
              >
                <Icon aria-hidden="true" size={17} />
                <span>{label}</span>
              </a>
            ))}
          </div>
        ))}
        {isAdmin && (
          <div className="nav-group">
            <span className="nav-group-label">Sistem</span>
            <a
              aria-label="Pengguna"
              aria-current={activeView === "users" ? "page" : undefined}
              className={activeView === "users" ? "active" : ""}
              href="#/users"
              onClick={(event) => {
                if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) onNavigate("users");
              }}
              title={collapsed ? "Pengguna" : undefined}
            >
              <Users aria-hidden="true" size={17} />
              <span>Pengguna</span>
            </a>
            <a
              aria-label="Audit log"
              aria-current={activeView === "audit" ? "page" : undefined}
              className={activeView === "audit" ? "active" : ""}
              href="#/audit"
              onClick={(event) => {
                if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) onNavigate("audit");
              }}
              title={collapsed ? "Audit log" : undefined}
            >
              <History aria-hidden="true" size={17} />
              <span>Log audit</span>
            </a>
            <a
              aria-label="Kesehatan sistem"
              aria-current={activeView === "system" ? "page" : undefined}
              className={activeView === "system" ? "active" : ""}
              href="#/system"
              onClick={(event) => {
                if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) onNavigate("system");
              }}
              title={collapsed ? "Kesehatan sistem" : undefined}
            >
              <Settings2 aria-hidden="true" size={17} />
              <span>Kesehatan sistem</span>
            </a>
          </div>
        )}
      </nav>
      <div className="sidebar-footer">
        <Boxes size={15} />
        <span>Community edition</span>
      </div>
    </aside>
  );
}
