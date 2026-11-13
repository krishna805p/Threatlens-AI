import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

export const apiService = {
  // Health
  checkHealth: async () => {
    const res = await api.get('/health');
    return res.data;
  },

  // Single Item Scan (URL, Email, SMS, Text)
  analyze: async (source, content) => {
    const res = await api.post('/analyze', { source, content });
    return res.data;
  },

  // Chrome Extension compatible predict
  predictUrl: async (url) => {
    const res = await api.post('/predict', { url });
    return res.data;
  },

  // Report False Positive / Trust Domain
  reportFalsePositive: async (url) => {
    const res = await api.post('/feedback/false-positive', { url });
    return res.data;
  },

  // Write Log Entry
  logEvent: async (logData) => {
    const res = await api.post('/log', logData);
    return res.data;
  },

  // CSV Batch Scan
  batchScan: async (rows) => {
    const res = await api.post('/batch', { rows });
    return res.data;
  },

  // Pipeline Events Ingestion & Lookup
  ingestEvent: async (source, content, priority = 'normal') => {
    const res = await api.post('/api/v1/events', { source, content, priority });
    return res.data;
  },

  getEventById: async (eventId) => {
    const res = await api.get(`/api/v1/events/${eventId}`);
    return res.data;
  },

  // Live Telemetry Stream
  getLiveLatest: async () => {
    const res = await api.get('/api/v1/live/latest');
    return res.data;
  },

  sendLiveTelemetry: async (url, source = 'chrome_extension') => {
    const res = await api.post('/api/v1/live/telemetry', { url, source });
    return res.data;
  },

  // Logs & History
  getLogs: async (limit = 50, risk = null) => {
    const params = { limit };
    if (risk && risk !== 'All') {
      params.risk = risk;
    }
    const res = await api.get('/logs', { params });
    return res.data;
  },

  // System Metrics
  getMetrics: async () => {
    const res = await api.get('/metrics');
    return res.data;
  },

  // Gemini AI Assistant Explanation
  explainDetection: async (detection, question = 'Explain this detection and recommend safe next steps.', history = []) => {
    const res = await api.post('/explain', { detection, question, history });
    return res.data;
  },

  // Gmail Integrations
  getGmailStatus: async () => {
    const res = await api.get('/api/v1/gmail/status');
    return res.data;
  },

  getGmailAuthUrl: async (returnTo = null) => {
    const params = returnTo ? { return_to: returnTo } : {};
    const res = await api.get('/api/v1/gmail/auth/login', { params });
    return res.data;
  },

  disconnectGmail: async () => {
    const res = await api.post('/api/v1/gmail/disconnect');
    return res.data;
  },

  authenticateGmail: async () => {
    const res = await api.post('/api/v1/gmail/auth');
    return res.data;
  },

  getGmailMessages: async (limit = 20) => {
    const numericLimit = typeof limit === 'number' && !isNaN(limit) ? limit : (parseInt(limit, 10) || 20);
    const res = await api.get('/api/v1/gmail/messages', { params: { limit: numericLimit } });
    return res.data;
  },

  getGmailMessageDetails: async (messageId) => {
    const res = await api.get(`/api/v1/gmail/messages/${messageId}`);
    return res.data;
  },

  analyzeGmailMessage: async (messageId) => {
    const res = await api.post(`/api/v1/gmail/messages/${messageId}/analyze`, {}, { timeout: 60000 });
    return res.data;
  },

  scanGmailInbox: async (limit = 20) => {
    const numericLimit = typeof limit === 'number' && !isNaN(limit) ? limit : (parseInt(limit, 10) || 20);
    const res = await api.post('/api/v1/gmail/scan', { limit: numericLimit }, { timeout: 120000 });
    return res.data;
  },
};

export default apiService;
