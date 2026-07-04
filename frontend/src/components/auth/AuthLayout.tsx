import type React from "react";
import { BrandLockup } from "../brand/BrandLockup";

export function AuthLayout({ eyebrow, title, children }: { eyebrow: string; title: string; children: React.ReactNode }) {
  return (
    <main className="auth-page">
      <section className="auth-branding">
        <BrandLockup inverse />
        <div className="auth-brand-message">
          <span>Own your intelligence.</span>
          <p>Collect, enrich, investigate, and operationalize open-source threat data from your own infrastructure.</p>
        </div>
      </section>
      <section className="auth-panel">
        <div className="auth-heading">
          <span className="eyebrow">{eyebrow}</span>
          <h1>{title}</h1>
          <p>ThreatLens analyst workspace</p>
        </div>
        {children}
      </section>
    </main>
  );
}
