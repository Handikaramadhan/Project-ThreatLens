export type AuditLogItem = {
  id: number;
  actor_id: number | null;
  actor_username: string;
  action: string;
  target_type: string;
  target_id: string;
  status: string;
  ip_address: string;
  details: string;
  created_at: string;
};

export type SystemHealth = {
  service: string;
  database: string;
  redis: string;
  alembic_revision: string;
  latest_collection_status: string;
  latest_collection_started_at: string | null;
  latest_collection_finished_at: string | null;
  audit_events: number;
  failed_alert_deliveries: number;
};

async function adminRequest<T>(url: string): Promise<T> {
  const response = await fetch(url, { credentials: "same-origin" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(typeof body.detail === "string" ? body.detail : "Request failed");
  }
  return response.json();
}

export function fetchAuditLogs() {
  return adminRequest<AuditLogItem[]>("/api/admin/audit-logs");
}

export function fetchSystemHealth() {
  return adminRequest<SystemHealth>("/api/admin/system-health");
}
