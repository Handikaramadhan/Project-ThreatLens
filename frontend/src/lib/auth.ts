export type UserRole = "admin" | "user";

export type User = {
  id: number;
  username: string;
  role: UserRole;
  active: boolean;
  created_at: string;
};

export type AuthSession = {
  user: User;
  csrf_token: string;
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
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json();
}

export function fetchAuthStatus() {
  return request<{ initialized: boolean }>("/api/auth/status");
}

export function bootstrapAdmin(username: string, password: string) {
  return request<{ status: string }>("/api/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });
}

export function login(username: string, password: string) {
  return request<AuthSession>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });
}

export function fetchCurrentSession() {
  return request<AuthSession>("/api/auth/me");
}

export function logout(csrfToken: string) {
  return request<void>("/api/auth/logout", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken }
  });
}

export function fetchUsers() {
  return request<User[]>("/api/admin/users");
}

export function createUser(username: string, password: string, role: UserRole, csrfToken: string) {
  return request<User>("/api/admin/users", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ username, password, role })
  });
}

export function deleteUser(userId: number, csrfToken: string) {
  return request<void>(`/api/admin/users/${userId}`, {
    method: "DELETE",
    headers: { "X-CSRF-Token": csrfToken }
  });
}
