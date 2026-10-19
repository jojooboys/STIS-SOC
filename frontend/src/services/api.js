// Gunakan cookie sesi pada proxy /api; hanya kegagalan sesi non-auth yang mengalihkan ke login.
import axios from 'axios';

const apiInstance = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

apiInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    const isAuthEndpoint = error.config?.url?.includes('/auth/');
    if (error.response?.status === 401 && !isAuthEndpoint && window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

const api = {
  // Auth
  login: (username, password) => apiInstance.post('/auth/login', { username, password }),
  logout: () => apiInstance.post('/auth/logout'),
  getMe: () => apiInstance.get('/auth/me'),

  // Dashboard
  getStats: () => apiInstance.get('/dashboard/stats'),
  getTimeline: () => apiInstance.get('/dashboard/timeline'),
  getTopSources: () => apiInstance.get('/dashboard/top-sources'),
  getSeverityDistribution: () => apiInstance.get('/dashboard/severity-distribution'),

  // Alerts
  getAlerts: (params) => apiInstance.get('/alerts', { params }),
  getAlert: (id) => apiInstance.get(`/alerts/${id}`),
  fetchAlerts: () => apiInstance.post('/alerts/fetch'),
  previewAlertPurge: (period) => apiInstance.post('/alerts/purge/preview', { period }),
  confirmAlertPurge: (token, password, phrase) => apiInstance.post('/alerts/purge/confirm', { token, password, phrase }),
  getAlertPurge: (id) => apiInstance.get(`/alerts/purge/${id}`),
  getActiveAlertPurge: () => apiInstance.get('/alerts/purge/active'),

  // Blocked IPs
  getBlockedIPs: (params) => apiInstance.get('/blocked-ips', { params }),
  blockIP: (ip_address, reason) => apiInstance.post('/blocked-ips', { ip_address, reason }),
  unblockIP: (id) => apiInstance.delete(`/blocked-ips/${id}`),
  reblockIP: (id) => apiInstance.post(`/blocked-ips/${id}/reblock`),
  deleteUnblockedHistory: (ids) => apiInstance.delete('/blocked-ips/history', { data: { ids } }),
  syncBlockedIPs: () => apiInstance.post('/blocked-ips/sync'),

  // Audit
  getAuditLogs: (params) => apiInstance.get('/audit', { params }),

  // Settings
  getSettings: () => apiInstance.get('/settings'),
  updateSettings: (data) => apiInstance.put('/settings', data),
  testWazuh: () => apiInstance.post('/settings/test-wazuh'),
  testPfSense: () => apiInstance.post('/settings/test-pfsense'),
  getAutoResponseStatus: () => apiInstance.get('/settings/auto-response-status'),

  // Inventory only: registration and monitoring are configured on each Agent.
  getAssetAgents: () => apiInstance.get('/assets/agents'),
  getAgentInventory: (id) => apiInstance.get(`/assets/agents/${encodeURIComponent(id)}/inventory`),
};

export default api;
