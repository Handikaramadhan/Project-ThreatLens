import { Activity, Bell, ChevronDown, LogOut, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { User } from "../../lib/auth";

type Props = {
  apiStatus: "loading" | "live" | "unavailable";
  eyebrow: string;
  onAlerts: () => void;
  onLogout: () => void;
  title: string;
  user: User;
};

export function Topbar({ apiStatus, eyebrow, onAlerts, onLogout, title, user }: Props) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;

    function closeMenu(event: MouseEvent | KeyboardEvent) {
      if (event instanceof KeyboardEvent && event.key === "Escape") {
        setMenuOpen(false);
        return;
      }
      if (event instanceof MouseEvent && !menuRef.current?.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }

    window.addEventListener("mousedown", closeMenu);
    window.addEventListener("keydown", closeMenu);
    return () => {
      window.removeEventListener("mousedown", closeMenu);
      window.removeEventListener("keydown", closeMenu);
    };
  }, [menuOpen]);

  return (
    <header className="topbar">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
      </div>
      <div className="topbar-actions">
        <div className="status-pill">
          <Activity size={14} />
          {apiStatus !== "loading" && <span className={apiStatus === "live" ? "dot live" : "dot"} />}
          {apiStatus === "live" ? "Data terkini" : apiStatus === "loading" ? "Memuat data…" : "API tidak tersedia"}
        </div>
        <div className="profile-menu" ref={menuRef}>
          <button
            aria-expanded={menuOpen}
            aria-label="Menu akun"
            className={menuOpen ? "profile-trigger open" : "profile-trigger"}
            onClick={() => setMenuOpen((open) => !open)}
            title="Menu akun"
            type="button"
          >
            <span className="profile-avatar">{user.username.charAt(0).toUpperCase()}</span>
            <ChevronDown className="profile-chevron" size={15} />
          </button>
          {menuOpen && (
            <div className="profile-dropdown">
              <div className="profile-identity">
                <span className="profile-avatar large">{user.username.charAt(0).toUpperCase()}</span>
                <div>
                  <strong>{user.username}</strong>
                  <span><ShieldCheck size={13} />{user.role}</span>
                </div>
              </div>
              <button
                onClick={() => {
                  setMenuOpen(false);
                  onAlerts();
                }}
                type="button"
              >
                <Bell size={17} />
                Pengaturan peringatan
              </button>
              <button onClick={onLogout} type="button">
                <LogOut size={17} />
                Keluar
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
