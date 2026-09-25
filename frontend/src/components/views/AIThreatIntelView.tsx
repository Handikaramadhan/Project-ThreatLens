import {
  Bot,
  CircleAlert,
  MessageSquare,
  Plus,
  Send,
  Sparkles,
  Trash2,
} from "lucide-react";
import { FormEvent, useEffect, useRef, useState } from "react";
import {
  createAIConversation,
  deleteAIConversation,
  fetchAIConversations,
  fetchAIMessages,
  fetchAIStatus,
  sendAIMessage,
  type AIConversation,
  type AIMessage,
  type AIStatus,
} from "../../lib/ai";

const suggestions = [
  "Ringkas risiko CVE-2026-46817 dan prioritas mitigasinya",
  "Buat checklist investigasi untuk IOC yang diduga bagian dari ransomware",
  "Apa data yang perlu dikumpulkan untuk memvalidasi eksploitasi CVE?",
];

type Props = {
  csrfToken: string;
};

export function AIThreatIntelView({ csrfToken }: Props) {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [conversations, setConversations] = useState<AIConversation[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [messages, setMessages] = useState<AIMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const messageEnd = useRef<HTMLDivElement>(null);
  const activeIdRef = useRef<number | null>(null);
  const messageRequestId = useRef(0);

  function selectConversation(id: number | null) {
    activeIdRef.current = id;
    setActiveId(id);
  }

  useEffect(() => {
    let active = true;
    Promise.all([fetchAIStatus(), fetchAIConversations()])
      .then(([nextStatus, rows]) => {
        if (!active) return;
        setStatus(nextStatus);
        setConversations(rows);
        if (rows[0]) selectConversation(rows[0].id);
      })
      .catch((reason) => { if (active) setError(reason instanceof Error ? reason.message : "AI workspace gagal dimuat."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const currentRequest = ++messageRequestId.current;
    setMessages([]);
    if (activeId === null) {
      return;
    }
    setError("");
    fetchAIMessages(activeId)
      .then((rows) => { if (currentRequest === messageRequestId.current) setMessages(rows); })
      .catch((reason) => { if (currentRequest === messageRequestId.current) setError(reason instanceof Error ? reason.message : "Percakapan gagal dimuat."); });
    return () => { messageRequestId.current += 1; };
  }, [activeId]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  async function newConversation() {
    setError("");
    try {
      const conversation = await createAIConversation(csrfToken);
      setConversations((current) => [conversation, ...current]);
      selectConversation(conversation.id);
      setMessages([]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Conversation gagal dibuat.");
    }
  }

  async function removeConversation(id: number) {
    const conversation = conversations.find((item) => item.id === id);
    if (!window.confirm(`Hapus percakapan "${conversation?.title || "ini"}"? Tindakan ini tidak dapat dibatalkan.`)) return;
    setError("");
    try {
      await deleteAIConversation(id, csrfToken);
      const remaining = conversations.filter((item) => item.id !== id);
      setConversations(remaining);
      if (activeIdRef.current === id) selectConversation(remaining[0]?.id ?? null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Conversation gagal dihapus.");
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const content = draft.trim();
    if (!content || sending || !status?.reachable) return;
    setError("");
    setSending(true);
    setDraft("");
    let conversationId = activeId;
    try {
      if (conversationId === null) {
        const conversation = await createAIConversation(csrfToken);
        conversationId = conversation.id;
        selectConversation(conversation.id);
        setConversations((current) => [conversation, ...current]);
      }
      messageRequestId.current += 1;
      const result = await sendAIMessage(conversationId, content, csrfToken);
      if (activeIdRef.current === conversationId) {
        try {
          const rows = await fetchAIMessages(conversationId);
          if (activeIdRef.current === conversationId) {
            messageRequestId.current += 1;
            setMessages(rows);
          }
        } catch {
          if (activeIdRef.current === conversationId) {
            messageRequestId.current += 1;
            setMessages((current) => [...current, result.user_message, result.assistant_message]);
          }
        }
      }
      try {
        setConversations(await fetchAIConversations());
      } catch {
        setError("Jawaban terkirim, tetapi daftar percakapan belum diperbarui.");
      }
    } catch (reason) {
      if (activeIdRef.current === conversationId) setDraft(content);
      setError(reason instanceof Error ? reason.message : "PicoClaw gagal menjawab.");
    } finally {
      setSending(false);
    }
  }

  return (
    <section className="ai-workspace">
      <aside className="ai-history">
        <div className="ai-history-header">
          <div>
            <span className="eyebrow">Private history</span>
            <strong>Investigations</strong>
          </div>
          <button aria-label="Percakapan baru" onClick={newConversation} title="Percakapan baru" type="button">
            <Plus size={17} />
          </button>
        </div>
        <div className="ai-conversation-list">
          {conversations.map((conversation) => (
            <div className={activeId === conversation.id ? "ai-conversation active" : "ai-conversation"} key={conversation.id}>
              <button aria-current={activeId === conversation.id ? "true" : undefined} onClick={() => selectConversation(conversation.id)} type="button">
                <MessageSquare size={15} />
                <span>
                  <strong>{conversation.title}</strong>
                  <small>{new Date(conversation.updated_at).toLocaleDateString("id-ID")}</small>
                </span>
              </button>
              <button
                aria-label={`Hapus ${conversation.title}`}
                className="ai-delete-conversation"
                onClick={() => void removeConversation(conversation.id)}
                title="Hapus percakapan"
                type="button"
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
          {!loading && conversations.length === 0 && (
            <p className="ai-history-empty">Belum ada investigation.</p>
          )}
        </div>
      </aside>

      <div className="ai-chat">
        <header className="ai-chat-header">
          <div className="ai-agent-mark"><Bot size={20} /></div>
          <div>
            <strong>ThreatLens AI Analyst</strong>
            <span className={status?.reachable ? "ai-status ready" : "ai-status"}>
              <i />{status?.reachable ? `${status.provider || "PicoClaw"} / ${status.model || "default model"}` : status?.message || "Checking PicoClaw…"}
            </span>
          </div>
        </header>

        <div className="ai-messages" aria-live="polite">
          {messages.length === 0 && !loading && (
            <div className="ai-welcome">
              <Sparkles size={25} />
              <h2>Mulai threat investigation</h2>
              <p>Tanyakan CVE, IOC, attack path, detection strategy, atau prioritas mitigasi.</p>
              <div className="ai-suggestions">
                {suggestions.map((suggestion) => (
                  <button disabled={!status?.reachable} key={suggestion} onClick={() => setDraft(suggestion)} type="button">
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          )}
          {messages.map((message) => (
            <article className={`ai-message ${message.role}`} key={message.id}>
              <div className="ai-message-role">{message.role === "assistant" ? <Bot size={16} /> : "You"}</div>
              <div>
                <p>{message.content}</p>
                <time>{new Date(message.created_at).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" })}</time>
              </div>
            </article>
          ))}
          {sending && (
            <div aria-live="polite" className="ai-thinking" role="status">
              <span /><span /><span />
              PicoClaw sedang menganalisis
            </div>
          )}
          <div ref={messageEnd} />
        </div>

        {error && <div className="ai-error"><CircleAlert size={15} />{error}</div>}
        <form className="ai-composer" onSubmit={submit}>
          <textarea
            aria-label="Pertanyaan threat intelligence"
            disabled={!status?.reachable || sending}
            maxLength={8000}
            name="threat_intel_question"
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
            placeholder={status?.reachable ? "Tulis pertanyaan atau CVE yang ingin diinvestigasi…" : "PicoClaw belum dikonfigurasi"}
            rows={3}
            value={draft}
          />
          <button aria-label="Kirim" disabled={!draft.trim() || sending || !status?.reachable} title="Kirim" type="submit">
            <Send size={18} />
          </button>
          <small>AI dapat keliru. Verifikasi temuan penting terhadap sumber yang ditampilkan.</small>
        </form>
      </div>
    </section>
  );
}
