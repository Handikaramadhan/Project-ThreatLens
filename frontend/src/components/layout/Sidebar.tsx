import {
  Bell,
  Boxes,
  FileText,
  LayoutDashboard,
  Radar,
  Search,
  Server,
  Shield,
  Sparkles,
  Users
} from "lucide-react";
import { BrandLockup } from "../brand/BrandLockup";
import type { ViewKey } from "../types";

const navGroups = [
  {
    label: "Workspace",
    items: [["Overview", LayoutDashboard, "dashboard"]]
  },
  {
    label: "Intelligence",
    items: [
      ["AI Intel", Sparkles, "ai"],
      ["Vulnerabilities", Shield, "cve"],
      ["Threat feed", Radar, "feed"],
      ["Indicators", Search, "ioc"]
    ]
  },
  {
    label: "Operations",
    items: [
      ["Assets", Server, "assets"],
      ["Alerts", Bell, "alerts"],
      ["Reports", FileText, "reports"]
    ]
  }
] as const;

type Props = {
  activeView: ViewKey;
  collapsed: boolean;
  isAdmin: boolean;
  onNavigate: (view: ViewKey) => void;
  onToggle: () => void;
};

export function Sidebar({ activeView, collapsed, isAdmin, onNavigate, onToggle }: Props) {
  return (
    <aside className={collapsed ? "sidebar collapsed" : "sidebar"}>
      <div className="brand">
        <button
          aria-label={collapsed ? "Tampilkan menu" : "Sembunyikan menu"}
          className="brand-toggle"
          onClick={onToggle}
          title={collapsed ? "Tampilkan menu" : "Sembunyikan menu"}
          type="button"
        >
          <BrandLockup compact={collapsed} />
        </button>
      </div>

      <nav aria-label="Primary navigation">
        {navGroups.map((group) => (
          <div className="nav-group" key={group.label}>
            <span className="nav-group-label">{group.label}</span>
            {group.items.map(([label, Icon, view]) => (
              <button
                aria-label={label}
                className={activeView === view ? "active" : ""}
                key={view}
                onClick={() => onNavigate(view)}
                title={collapsed ? label : undefined}
                type="button"
              >
                <Icon size={17} />
                <span>{label}</span>
              </button>
            ))}
          </div>
        ))}
        {isAdmin && (
          <div className="nav-group">
            <span className="nav-group-label">System</span>
            <button
              aria-label="Users"
              className={activeView === "users" ? "active" : ""}
              onClick={() => onNavigate("users")}
              title={collapsed ? "Users" : undefined}
              type="button"
            >
              <Users size={17} />
              <span>Users</span>
            </button>
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
