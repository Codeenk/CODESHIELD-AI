const BASE = "/api/v1";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, {
    credentials: "include",
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(options.headers || {}),
    },
  });
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("json") ? await response.json().catch(() => null) : await response.text();
  if (!response.ok) {
    const detail = payload?.detail;
    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg).join(", ")
      : detail || (typeof payload === "string" && payload) || `Request failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return payload;
}

export const api = {
  me: () => request("/auth/me"),
  login: (email, password) => request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  register: (name, email, password) =>
    request("/auth/register", { method: "POST", body: JSON.stringify({ name, email, password }) }),
  logout: () => request("/auth/logout", { method: "POST" }),
  meta: () => request("/meta"),
  stats: (days = 14) => request(`/stats?days=${days}`),
  scans: (params = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== "") query.set(key, value);
    });
    return request(`/scans?${query.toString()}`);
  },
  scan: (id) => request(`/scans/${id}`),
  createScan: (formData) => request("/scans", { method: "POST", body: formData }),
  cancelScan: (id) => request(`/scans/${id}/cancel`, { method: "POST" }),
  deleteScan: (id) => request(`/scans/${id}`, { method: "DELETE" }),
  compare: (base, head) => request(`/scans/compare?base=${encodeURIComponent(base)}&head=${encodeURIComponent(head)}`),
  updateFinding: (id, status, note = "") =>
    request(`/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status, note }) }),
  findingEvents: (id) => request(`/findings/${id}/events`),
  projects: () => request("/projects"),
  knowledge: () => request("/knowledge"),
  knowledgeItem: (slug) => request(`/knowledge/${slug}`),
  reportUrl: (id, format, download = false) =>
    `${BASE}/scans/${id}/report?format=${format}${download ? "&download=1" : ""}`,
  githubUrl: () => `${BASE}/auth/github`,
};

export function reportDownload(scanId, format) {
  const link = document.createElement("a");
  link.href = api.reportUrl(scanId, format, true);
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
}
