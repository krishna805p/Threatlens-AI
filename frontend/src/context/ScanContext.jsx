import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import apiService from '../api/client';

const ScanContext = createContext();

const LATEST_STORAGE_KEY = 'threatlens_latest_url_scan';
const RECENT_STORAGE_KEY = 'threatlens_recent_url_scans';

const formatScanData = (url, data, defaultSource = 'MANUAL SCAN') => {
  const riskLevel = data.risk_level || data.risk || 'Unknown';
  const riskScore = typeof data.risk_score === 'number' 
    ? data.risk_score 
    : typeof data.score === 'number' 
    ? data.score 
    : (parseFloat(data.risk_score || data.score) || 0);

  const probability = typeof data.probability === 'number' 
    ? data.probability 
    : typeof data.ml_probability === 'number'
    ? data.ml_probability
    : typeof data.ml_prob === 'number' 
    ? data.ml_prob 
    : (parseFloat(data.probability || data.ml_probability || data.ml_prob) || 0);

  const reasons = Array.isArray(data.reasons) 
    ? data.reasons 
    : Array.isArray(data.reason)
    ? data.reason
    : data.reason
    ? [String(data.reason)]
    : data.reasons
    ? [String(data.reasons)]
    : [];

  const status = data.prediction || data.detection_status || riskLevel || 'Scanned';
  const sourceLabel = (data.source || defaultSource).toUpperCase();

  return {
    id: data.id || `scan-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    url: String(url || data.url || data.input || 'Unknown URL').trim(),
    risk_level: riskLevel,
    risk_score: riskScore,
    probability: probability,
    ml_probability: probability,
    ml_prob: probability,
    reasons: reasons,
    reason: reasons,
    detection_status: status,
    prediction: status,
    source: sourceLabel,
    timestamp: data.timestamp || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    fullTimestamp: data.full_timestamp || new Date().toISOString(),
    debug: data.debug || null,
  };
};

export const ScanProvider = ({ children }) => {
  const [liveTelemetry, setLiveTelemetry] = useState({
    status: 'waiting',
    connected: false,
    latest: null,
    history: [],
  });

  const [manualScan, setManualScan] = useState(() => {
    try {
      const saved = localStorage.getItem(LATEST_STORAGE_KEY);
      return saved ? JSON.parse(saved) : null;
    } catch (e) {
      return null;
    }
  });

  const [recentUrlScans, setRecentUrlScansState] = useState(() => {
    try {
      const saved = localStorage.getItem(RECENT_STORAGE_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch (e) {
      return [];
    }
  });

  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState('');

  // Fetch backend live telemetry
  const fetchLiveTelemetry = useCallback(async () => {
    try {
      const data = await apiService.getLiveLatest();
      if (data) {
        const formattedLatest = data.latest ? formatScanData(data.latest.url, data.latest, data.latest.source || 'CHROME EXTENSION') : null;
        const formattedHistory = (data.history || []).map((h) => formatScanData(h.url, h, h.source || 'CHROME EXTENSION'));

        setLiveTelemetry({
          status: data.status || 'waiting',
          connected: Boolean(data.connected),
          latest: formattedLatest,
          history: formattedHistory,
        });

        if (formattedHistory.length > 0) {
          setRecentUrlScansState(formattedHistory);
          try {
            localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(formattedHistory));
          } catch (e) {}
        }
      }
    } catch (e) {
      setLiveTelemetry((prev) => ({ ...prev, connected: false }));
    }
  }, []);

  useEffect(() => {
    fetchLiveTelemetry();
    const interval = setInterval(fetchLiveTelemetry, 2500);
    return () => clearInterval(interval);
  }, [fetchLiveTelemetry]);

  // Combined latest scan: Prefer live backend browser telemetry, fall back to manual scan
  const activeLatestScan = liveTelemetry.latest || manualScan;

  const addUrlScan = (url, rawData) => {
    const formatted = formatScanData(url, rawData, 'MANUAL SCAN');
    setManualScan(formatted);
    try {
      localStorage.setItem(LATEST_STORAGE_KEY, JSON.stringify(formatted));
    } catch (e) {}

    setRecentUrlScansState((prev) => {
      const existing = prev || [];
      const filtered = existing.filter((item) => item.url.toLowerCase() !== formatted.url.toLowerCase());
      const updated = [formatted, ...filtered].slice(0, 10);
      try {
        localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(updated));
      } catch (e) {}
      return updated;
    });

    setScanError('');
  };

  const clearScans = () => {
    setManualScan(null);
    setLiveTelemetry({ status: 'waiting', connected: false, latest: null, history: [] });
    setRecentUrlScansState([]);
    try {
      localStorage.removeItem(LATEST_STORAGE_KEY);
      localStorage.removeItem(RECENT_STORAGE_KEY);
    } catch (e) {}
  };

  return (
    <ScanContext.Provider
      value={{
        latestUrlScan: activeLatestScan,
        liveTelemetry,
        recentUrlScans,
        addUrlScan,
        clearScans,
        scanLoading,
        setScanLoading,
        scanError,
        setScanError,
        refreshTelemetry: fetchLiveTelemetry,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};

export default ScanContext;
