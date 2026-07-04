export type AIStatus = {
  enabled: boolean;
  reachable: boolean;
  provider: string;
  model: string;
  message: string;
};

export type AIConversation = {
  id: number;
  title: string;
  created_at: string;
  updated_at: string;
};

export type AIMessage = {
  id: number;
  role: "user" | "assistant";
  content: string;
  citations: string[];
  created_at: string;
};

export type CVEAIEnrichment = {
  cve_id: string;
  executive_summary: string;
  product_inference: {
    vendor: string;
    product: string;
    versions: string[];
    confidence: number;
    evidence: string[];
  };
  attack_path: string[];
  business_impact: string[];
  detection_guidance: string[];
  mitigation: string[];
  workarounds: string[];
  analyst_notes: string[];
  citations: string[];
  provider: string;
  model: string;
  generated_at: string;
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: "AI request gagal." }));
    throw new Error(typeof body.detail === "string" ? body.detail : "AI request gagal.");
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

export function fetchAIStatus() {
  return api<AIStatus>("/api/ai/status");
}

export function fetchAIConversations() {
  return api<AIConversation[]>("/api/ai/conversations");
}

export function createAIConversation(csrfToken: string) {
  return api<AIConversation>("/api/ai/conversations", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ title: "New investigation" }),
  });
}

export function deleteAIConversation(conversationId: number, csrfToken: string) {
  return api<void>(`/api/ai/conversations/${conversationId}`, {
    method: "DELETE",
    headers: { "X-CSRF-Token": csrfToken },
  });
}

export function fetchAIMessages(conversationId: number) {
  return api<AIMessage[]>(`/api/ai/conversations/${conversationId}/messages`);
}

export async function sendAIMessage(
  conversationId: number,
  content: string,
  csrfToken: string,
): Promise<{ user_message: AIMessage; assistant_message: AIMessage }> {
  return api<{ user_message: AIMessage; assistant_message: AIMessage }>(
    `/api/ai/conversations/${conversationId}/messages`,
    {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ content }),
    },
  );
}

export function fetchCVEAIEnrichment(cveId: string) {
  return api<CVEAIEnrichment>(`/api/cves/${encodeURIComponent(cveId)}/ai-enrichment`);
}

export function generateCVEAIEnrichment(cveId: string, csrfToken: string) {
  return api<CVEAIEnrichment>(`/api/cves/${encodeURIComponent(cveId)}/ai-enrichment`, {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: "{}",
  });
}
