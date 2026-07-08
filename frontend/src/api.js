/**
 * CyberSec Suite API client — handles all backend communication.
 * Reads the base URL from environment or falls back to relative paths (proxy).
 */

const BASE = import.meta.env.VITE_API_URL || '/api';

function getToken() {
  return localStorage.getItem('cybersec_token');
}

function headers(json = true) {
  const h = {};
  if (json) h['Content-Type'] = 'application/json';
  const token = getToken();
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: headers(opts.json !== false),
    ...opts,
  });
  if (res.status === 401) {
    localStorage.removeItem('cybersec_token');
    localStorage.removeItem('cybersec_user');
    window.location.reload();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

// ──── Auth ────────────────────────────────────────────────────
export const auth = {
  register: (data) => request('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  login: async (username, password) => {
    const data = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    localStorage.setItem('cybersec_token', data.access_token);
    localStorage.setItem('cybersec_user', JSON.stringify({ id: data.user_id, role: data.role }));
    return data;
  },
  logout: () => {
    localStorage.removeItem('cybersec_token');
    localStorage.removeItem('cybersec_user');
  },
  isLoggedIn: () => !!getToken(),
  getUser: () => {
    try { return JSON.parse(localStorage.getItem('cybersec_user')); }
    catch { return null; }
  },
};

// ──── Scans ───────────────────────────────────────────────────
export const scans = {
  create: (target, scan_type, config = {}) =>
    request('/scans/', { method: 'POST', body: JSON.stringify({ target, scan_type, config }) }),
  list: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/scans/${q ? '?' + q : ''}`);
  },
  get: (id) => request(`/scans/${id}`),
  status: (id) => request(`/scans/${id}/status`),
  cancel: (id) => request(`/scans/${id}`, { method: 'DELETE' }),
  stats: () => request('/scans/stats/summary'),
};

// ──── Forensics ───────────────────────────────────────────────
export const forensics = {
  createCase: (title, description = '') =>
    request('/forensics/cases', { method: 'POST', body: JSON.stringify({ title, description }) }),
  listCases: () => request('/forensics/cases'),
  getCase: (id) => request(`/forensics/cases/${id}`),
  uploadLogs: async (caseId, file) => {
    const form = new FormData();
    form.append('file', file);
    const token = getToken();
    const res = await fetch(`${BASE}/forensics/cases/${caseId}/upload-logs`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: form,
    });
    if (!res.ok) throw new Error('Upload failed');
    return res.json();
  },
  yaraScan: async (caseId, file) => {
    const form = new FormData();
    form.append('file', file);
    const token = getToken();
    const res = await fetch(`${BASE}/forensics/cases/${caseId}/yara-scan`, {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: form,
    });
    if (!res.ok) throw new Error('YARA scan failed');
    return res.json();
  },
  getLogs: (caseId, params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/forensics/cases/${caseId}/logs${q ? '?' + q : ''}`);
  },
};

// ──── RCA ─────────────────────────────────────────────────────
export const rca = {
  createIncident: (data) =>
    request('/rca/incidents', { method: 'POST', body: JSON.stringify(data) }),
  listIncidents: () => request('/rca/incidents'),
  getIncident: (id) => request(`/rca/incidents/${id}`),
  correlate: (id) => request(`/rca/incidents/${id}/correlate`, { method: 'POST' }),
  analyze: (id) => request(`/rca/incidents/${id}/analyze`, { method: 'POST' }),
  updateRemediation: (incidentId, remId, status) =>
    request(`/rca/incidents/${incidentId}/remediations/${remId}?status=${status}`, { method: 'PATCH' }),
};

// ──── Dashboard ───────────────────────────────────────────────
export const dashboard = {
  stats: () => request('/dashboard/stats'),
  trend: (days = 7) => request(`/dashboard/trend?days=${days}`),
  alerts: (limit = 20) => request(`/dashboard/alerts?limit=${limit}`),
  markRead: (id) => request(`/dashboard/alerts/${id}/read`, { method: 'PATCH' }),
};

// ──── Reports ─────────────────────────────────────────────────
export const reports = {
  generate: (report_type, entity_id, include_sections = ['summary', 'findings', 'remediation', 'timeline']) =>
    request('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ report_type, entity_id, include_sections }),
    }),
  downloadUrl: (filename) => `${BASE.replace('/api', '')}/reports/${filename}`,
};
