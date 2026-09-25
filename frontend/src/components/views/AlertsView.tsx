import { Bell, CheckCircle2, MessageCircle, RefreshCw, Save, Send, Siren, Webhook, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  fetchAlertDeliveries,
  fetchAlertPreferences,
  testAlertChannel,
  updateAlertPreferences,
  type AlertDelivery,
  type AlertPreference,
  type AlertPreferenceInput,
  type AlertSeverity
} from "../../lib/alerts";
import { formatApiDateTime } from "../../lib/datetime";
import { Panel } from "../ui/Panel";

type Props = {
  csrfToken: string;
};

const severities: AlertSeverity[] = ["Low", "Medium", "High", "Critical"];
type AlertTab = "channels" | "events" | "history";

const eventOptions: Array<{ key: keyof AlertPreferenceInput; label: string; meta: string }> = [
  { key: "notify_news", label: "Threat news", meta: "Berita baru dari feed aktif" },
  { key: "notify_cve", label: "CVE baru", meta: "CVE/KEV baru yang masuk collector" },
  { key: "notify_asset_exposure", label: "Affected asset", meta: "Asset cocok dengan CVE" },
  { key: "notify_ioc", label: "IOC", meta: "Disiapkan untuk rule IOC berikutnya" },
  { key: "notify_source_health", label: "Source health", meta: "Source collection error" }
];

function toEditable(preference: AlertPreference): AlertPreferenceInput {
  return {
    ...preference,
    telegram_bot_token: "",
    clear_telegram_bot_token: false,
    discord_webhook_url: "",
    clear_discord_webhook: false
  };
}

function statusIcon(status: string) {
  return status === "sent" ? <CheckCircle2 size={15} /> : <XCircle size={15} />;
}

export function AlertsView({ csrfToken }: Props) {
  const [preference, setPreference] = useState<AlertPreferenceInput | null>(null);
  const [deliveries, setDeliveries] = useState<AlertDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<"telegram" | "discord" | null>(null);
  const [activeTab, setActiveTab] = useState<AlertTab>("channels");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [historyError, setHistoryError] = useState("");

  async function load() {
    setError("");
    setHistoryError("");
    setLoading(true);
    const [settingsResult, deliveriesResult] = await Promise.allSettled([
      fetchAlertPreferences(),
      fetchAlertDeliveries()
    ]);
    if (settingsResult.status === "fulfilled") {
      setPreference(toEditable(settingsResult.value));
    } else {
      setError(settingsResult.reason instanceof Error ? settingsResult.reason.message : "Gagal memuat alert settings.");
    }
    if (deliveriesResult.status === "fulfilled") {
      setDeliveries(deliveriesResult.value);
    } else {
      setHistoryError(deliveriesResult.reason instanceof Error ? deliveriesResult.reason.message : "Gagal memuat riwayat alert.");
    }
    setLoading(false);
  }

  async function refreshDeliveries() {
    setHistoryError("");
    try {
      setDeliveries(await fetchAlertDeliveries());
    } catch (err) {
      setHistoryError(err instanceof Error ? err.message : "Gagal memuat riwayat alert.");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const channelsReady = useMemo(() => {
    if (!preference) return false;
    return (
      (
        preference.telegram_enabled &&
        preference.telegram_chat_id.trim() !== "" &&
        (preference.telegram_bot_token.trim() !== "" || preference.telegram_bot_configured)
      ) ||
      (preference.discord_enabled && (preference.discord_webhook_url.trim() !== "" || preference.discord_webhook_configured))
    );
  }, [preference]);

  async function save() {
    if (!preference) return;
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const saved = await updateAlertPreferences(preference, csrfToken);
      setPreference(toEditable(saved));
      setMessage("Alert settings tersimpan.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Gagal menyimpan alert settings");
    } finally {
      setSaving(false);
    }
  }

  async function sendTest(channel: "telegram" | "discord") {
    if (!preference) return;
    setTesting(channel);
    setError("");
    setMessage("");
    try {
      const testPayload = channel === "telegram"
        ? {
          telegram_bot_token: preference.telegram_bot_token,
          telegram_chat_id: preference.telegram_chat_id
        }
        : {
          discord_webhook_url: preference.discord_webhook_url
        };
      await testAlertChannel(channel, csrfToken, testPayload);
      setMessage(`Test ${channel} terkirim.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Gagal test ${channel}`);
    } finally {
      setTesting(null);
    }
  }

  function patch<K extends keyof AlertPreferenceInput>(key: K, value: AlertPreferenceInput[K]) {
    setPreference((current) => current ? { ...current, [key]: value } : current);
  }

  if (!preference) {
    return (
      <section className="view-grid">
        <Panel title="Alert Settings" icon={<Bell size={18} />} wide>
          {loading ? (
            <div className="alert-loading" role="status"><RefreshCw size={16} /> Memuat alert settings…</div>
          ) : (
            <div className="alert-load-error">
              <div className="form-error" role="alert">{error || "Gagal memuat alert settings."}</div>
              <button className="button-secondary refresh-button" onClick={() => void load()} type="button"><RefreshCw size={15} />Coba lagi</button>
            </div>
          )}
        </Panel>
      </section>
    );
  }

  return (
    <section className="alerts-page">
      <Panel
        title="Alert Settings"
        icon={<Bell size={18} />}
        wide
        action={
          <button className="button-primary" disabled={saving} onClick={save} type="button">
            <Save size={16} />
            {saving ? "Menyimpan…" : "Save"}
          </button>
        }
      >
        <div className="alert-tabs" role="group" aria-label="Bagian pengaturan alert">
          {[
            ["channels", "Channels"],
            ["events", "Events"],
            ["history", "History"]
          ].map(([key, label]) => (
            <button
              aria-pressed={activeTab === key}
              className={activeTab === key ? "active" : ""}
              key={key}
              onClick={() => setActiveTab(key as AlertTab)}
              type="button"
            >
              {label}
            </button>
          ))}
        </div>
        <div className="alert-settings-grid">
          <label className="alert-switch">
            <input
              checked={preference.enabled}
              name="alerts_enabled"
              onChange={(event) => patch("enabled", event.target.checked)}
              type="checkbox"
            />
            <span>
              <strong>Enable alerts</strong>
              <small>{channelsReady ? "Delivery channel siap." : "Aktifkan minimal satu channel dulu."}</small>
            </span>
          </label>

          {activeTab === "channels" && <div className="alert-channel">
            <div className="alert-channel-header">
              <MessageCircle size={18} />
              <div>
                <strong>Telegram</strong>
                <small>{preference.telegram_bot_configured ? "Bot token tersimpan" : "Bot token belum disimpan"}</small>
              </div>
            </div>
            <label className="alert-switch compact">
              <input
                checked={preference.telegram_enabled}
                name="telegram_enabled"
                onChange={(event) => patch("telegram_enabled", event.target.checked)}
                type="checkbox"
              />
              <span>Aktif</span>
            </label>
            <label className="alert-field">
              <span>Bot token</span>
              <input
                onChange={(event) => patch("telegram_bot_token", event.target.value)}
                name="telegram_bot_token"
                placeholder={preference.telegram_bot_configured ? "Biarkan kosong untuk tetap pakai token tersimpan" : "1234567890:AA…"}
                type="password"
                value={preference.telegram_bot_token}
              />
            </label>
            <label className="alert-field">
              <span>Chat ID</span>
              <input
                onChange={(event) => patch("telegram_chat_id", event.target.value)}
                name="telegram_chat_id"
                placeholder="-1001234567890"
                value={preference.telegram_chat_id}
              />
            </label>
            <label className="alert-switch compact">
              <input
                checked={preference.clear_telegram_bot_token}
                disabled={!preference.telegram_bot_configured}
                name="clear_telegram_bot_token"
                onChange={(event) => patch("clear_telegram_bot_token", event.target.checked)}
                type="checkbox"
              />
              <span>Hapus token tersimpan</span>
            </label>
            <button
              className="button-secondary"
              disabled={testing !== null || !preference.telegram_enabled}
              onClick={() => void sendTest("telegram")}
              type="button"
            >
              <Send size={15} />
              {testing === "telegram" ? "Testing…" : "Test Telegram"}
            </button>
          </div>}

          {activeTab === "channels" && <div className="alert-channel">
            <div className="alert-channel-header">
              <Webhook size={18} />
              <div>
                <strong>Discord</strong>
                <small>{preference.discord_webhook_configured ? preference.discord_webhook_hint : "Webhook belum disimpan"}</small>
              </div>
            </div>
            <label className="alert-switch compact">
              <input
                checked={preference.discord_enabled}
                name="discord_enabled"
                onChange={(event) => patch("discord_enabled", event.target.checked)}
                type="checkbox"
              />
              <span>Aktif</span>
            </label>
            <label className="alert-field">
              <span>Webhook URL</span>
              <input
                onChange={(event) => patch("discord_webhook_url", event.target.value)}
                name="discord_webhook_url"
                placeholder={preference.discord_webhook_configured ? "Biarkan kosong untuk tetap pakai webhook tersimpan" : "https://discord.com/api/webhooks/…"}
                type="password"
                value={preference.discord_webhook_url}
              />
            </label>
            <label className="alert-switch compact">
              <input
                checked={preference.clear_discord_webhook}
                disabled={!preference.discord_webhook_configured}
                name="clear_discord_webhook"
                onChange={(event) => patch("clear_discord_webhook", event.target.checked)}
                type="checkbox"
              />
              <span>Hapus webhook tersimpan</span>
            </label>
            <button
              className="button-secondary"
              disabled={testing !== null || !preference.discord_enabled}
              onClick={() => void sendTest("discord")}
              type="button"
            >
              <Send size={15} />
              {testing === "discord" ? "Testing…" : "Test Discord"}
            </button>
          </div>}

          {activeTab === "events" && <div className="alert-events">
            <div className="alert-section-title">
              <Siren size={17} />
              <span>Event yang dikirim</span>
            </div>
            <div className="alert-event-list">
              {eventOptions.map((option) => (
                <label className="alert-event-option" key={option.key}>
                  <input
                    checked={Boolean(preference[option.key])}
                    name={option.key}
                    onChange={(event) => patch(option.key, event.target.checked as never)}
                    type="checkbox"
                  />
                  <span>
                    <strong>{option.label}</strong>
                    <small>{option.meta}</small>
                  </span>
                </label>
              ))}
            </div>
            <label className="alert-field severity-select">
              <span>Minimum CVE severity</span>
              <select
                name="minimum_severity"
                onChange={(event) => {
                  patch("minimum_severity", event.target.value as AlertSeverity);
                  patch("cve_minimum_severity", event.target.value as AlertSeverity);
                }}
                value={preference.cve_minimum_severity || preference.minimum_severity}
              >
                {severities.map((severity) => <option key={severity}>{severity}</option>)}
              </select>
            </label>
            <div className="alert-event-controls">
              <label className="alert-field">
                <span>Minimum asset exposure severity</span>
                <select
                  name="asset_exposure_minimum_severity"
                  onChange={(event) => patch("asset_exposure_minimum_severity", event.target.value as AlertSeverity)}
                  value={preference.asset_exposure_minimum_severity}
                >
                  {severities.map((severity) => <option key={severity}>{severity}</option>)}
                </select>
              </label>
              <label className="alert-field">
                <span>Minimum IOC severity</span>
                <select
                  name="ioc_minimum_severity"
                  onChange={(event) => patch("ioc_minimum_severity", event.target.value as AlertSeverity)}
                  value={preference.ioc_minimum_severity}
                >
                  {severities.map((severity) => <option key={severity}>{severity}</option>)}
                </select>
              </label>
              <label className="alert-field">
                <span>Source health mode</span>
                <select
                  name="source_health_alert_mode"
                  onChange={(event) => patch("source_health_alert_mode", event.target.value as "new_error" | "every_error")}
                  value={preference.source_health_alert_mode}
                >
                  <option value="new_error">Only new errors</option>
                  <option value="every_error">Every failed run</option>
                </select>
              </label>
            </div>
          </div>}
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        {message && <div className="form-success" role="status">{message}</div>}
      </Panel>

      {activeTab === "history" && <Panel
        title="Delivery History"
        icon={<Siren size={18} />}
        wide
        action={<button className="button-secondary refresh-button" onClick={() => void refreshDeliveries()} type="button"><RefreshCw size={15} />Muat ulang</button>}
      >
        {historyError && <div className="form-error" role="alert">{historyError}</div>}
        <div className="alert-history">
          {deliveries.length === 0 ? (
            <p className="alert-empty">Belum ada delivery alert.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Channel</th>
                  <th>Status</th>
                  <th>Retries</th>
                  <th>Severity</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {deliveries.map((delivery) => (
                  <tr key={delivery.id}>
                    <td>
                      <strong>{delivery.title}</strong>
                      <span>{delivery.error || delivery.event_type}</span>
                    </td>
                    <td>{delivery.channel}</td>
                    <td><span className={`alert-status ${delivery.status}`}>{statusIcon(delivery.status)}{delivery.status}</span></td>
                    <td>{delivery.retry_count}</td>
                    <td>{delivery.severity}</td>
                    <td>{formatApiDateTime(delivery.sent_at || delivery.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Panel>}
    </section>
  );
}
