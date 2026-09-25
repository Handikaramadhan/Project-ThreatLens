export type AlertSeverity = "Low" | "Medium" | "High" | "Critical";

export type AlertPreference = {
  enabled: boolean;
  telegram_enabled: boolean;
  telegram_bot_configured: boolean;
  telegram_chat_id: string;
  discord_enabled: boolean;
  discord_webhook_configured: boolean;
  discord_webhook_hint: string;
  notify_news: boolean;
  notify_cve: boolean;
  notify_asset_exposure: boolean;
  notify_ioc: boolean;
  notify_source_health: boolean;
  minimum_severity: AlertSeverity;
  cve_minimum_severity: AlertSeverity;
  asset_exposure_minimum_severity: AlertSeverity;
  ioc_minimum_severity: AlertSeverity;
  source_health_alert_mode: "new_error" | "every_error";
  updated_at: string | null;
};

export type AlertPreferenceInput = AlertPreference & {
  telegram_bot_token: string;
  clear_telegram_bot_token: boolean;
  discord_webhook_url: string;
  clear_discord_webhook: boolean;
};

export type AlertDelivery = {
  id: number;
  event_type: string;
  channel: "telegram" | "discord" | string;
  title: string;
  severity: string;
  status: "sent" | "failed" | string;
  retry_count: number;
  error: string;
  created_at: string;
  sent_at: string | null;
};

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers
    }
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(typeof body.detail === "string" ? body.detail : "Request failed");
  }
  return response.json();
}

export function fetchAlertPreferences() {
  return request<AlertPreference>("/api/alerts/preferences");
}

export function updateAlertPreferences(payload: AlertPreferenceInput, csrfToken: string) {
  const {
    discord_webhook_configured,
    discord_webhook_hint,
    telegram_bot_configured,
    updated_at,
    ...writePayload
  } = payload;
  void discord_webhook_configured;
  void discord_webhook_hint;
  void telegram_bot_configured;
  void updated_at;
  return request<AlertPreference>("/api/alerts/preferences", {
    method: "PUT",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify(writePayload)
  });
}

export function testAlertChannel(
  channel: "telegram" | "discord",
  csrfToken: string,
  payload: Partial<Pick<AlertPreferenceInput, "telegram_bot_token" | "telegram_chat_id" | "discord_webhook_url">> = {}
) {
  return request<{ status: "sent"; channel: "telegram" | "discord" }>("/api/alerts/test", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ channel, ...payload })
  });
}

export function fetchAlertDeliveries() {
  return request<AlertDelivery[]>("/api/alerts/deliveries");
}
