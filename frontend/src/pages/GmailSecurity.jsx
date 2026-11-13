import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Mail, RefreshCw, Loader2, ShieldCheck, AlertTriangle, ShieldAlert, Sparkles, Inbox, LogOut } from 'lucide-react';
import apiService from '../api/client';
import PageTransition from '../components/layout/PageTransition';
import ThreatBadge from '../components/threats/ThreatBadge';
import ThreatDetailsModal from '../components/ThreatDetailsModal';
import GeminiModal from '../components/GeminiModal';

export const GmailSecurity = () => {
  const [status, setStatus] = useState(null);
  const [messages, setMessages] = useState([]);
  const [scanLimit, setScanLimit] = useState(20);
  const [loading, setLoading] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [batchScanning, setBatchScanning] = useState(false);
  const [analyzingId, setAnalyzingId] = useState(null);
  const [analysisResults, setAnalysisResults] = useState({});
  const [error, setError] = useState('');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [geminiTarget, setGeminiTarget] = useState(null);

  const handleLoadMessages = async (limitParam) => {
    const limit = typeof limitParam === 'number' && !isNaN(limitParam)
      ? limitParam
      : (typeof scanLimit === 'number' && !isNaN(scanLimit) ? scanLimit : 20);
    setLoading(true);
    setError('');
    try {
      const msgs = await apiService.getGmailMessages(limit);
      setMessages(msgs || []);
      setAnalysisResults({});
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to retrieve Gmail messages. Reconnect Gmail.');
    } finally {
      setLoading(false);
    }
  };

  const handleScanSingleMessage = async (messageId) => {
    if (!messageId) return;
    setAnalyzingId(messageId);
    setError('');
    try {
      const res = await apiService.analyzeGmailMessage(messageId);
      if (res?.event) {
        setAnalysisResults((prev) => ({
          ...prev,
          [messageId]: res.event,
        }));
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze email message.');
    } finally {
      setAnalyzingId(null);
    }
  };

  const fetchStatus = async () => {
    try {
      const res = await apiService.getGmailStatus();
      setStatus(res);
      return res;
    } catch (err) {
      console.error('Failed to fetch Gmail status:', err);
      return null;
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const gmailStatus = params.get('gmail_status');
    const errorParam = params.get('error');

    if (gmailStatus === 'connected') {
      window.history.replaceState({}, document.title, window.location.pathname);
      fetchStatus().then((res) => {
        if (res?.connected) {
          handleLoadMessages();
        }
      });
    } else if (gmailStatus === 'error') {
      const msg = errorParam ? decodeURIComponent(errorParam) : 'OAuth authorization failed.';
      setError(`Gmail Authorization Error: ${msg}`);
      window.history.replaceState({}, document.title, window.location.pathname);
      fetchStatus();
    } else {
      fetchStatus();
    }
  }, []);

  const handleConnect = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await apiService.getGmailAuthUrl();
      if (res?.authorization_url) {
        window.location.href = res.authorization_url;
      } else {
        setError('Failed to obtain Google authorization URL from backend.');
        setLoading(false);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Gmail authorization failed. Check client credentials configuration.');
      setLoading(false);
    }
  };

  const handleDisconnect = async () => {
    if (!window.confirm('Disconnect Gmail account and remove stored credentials from the backend?')) {
      return;
    }
    setDisconnecting(true);
    setError('');
    try {
      await apiService.disconnectGmail();
      setMessages([]);
      setAnalysisResults({});
      await fetchStatus();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to disconnect Gmail.');
    } finally {
      setDisconnecting(false);
    }
  };


  const handleBatchScan = async () => {
    if (!messages.length) return;
    setBatchScanning(true);
    setError('');

    try {
      const numericLimit = typeof scanLimit === 'number' && !isNaN(scanLimit)
        ? scanLimit
        : (parseInt(scanLimit, 10) || 20);
      const scanRes = await apiService.scanGmailInbox(numericLimit);
      const newResults = {};
      (scanRes.events || []).forEach((item) => {
        if (item.event?.metadata?.gmail_message_id) {
          newResults[item.event.metadata.gmail_message_id] = item.event;
        }
      });
      setAnalysisResults((prev) => ({ ...prev, ...newResults }));
    } catch (err) {
      setError(err.response?.data?.detail || 'Batch Gmail scan failed.');
    } finally {
      setBatchScanning(false);
    }
  };

  // Metrics
  const fetchedCount = messages.length;
  let safeCount = 0;
  let suspiciousCount = 0;
  let highRiskCount = 0;

  Object.values(analysisResults).forEach((evt) => {
    const risk = evt?.assessment?.risk_level;
    if (risk === 'High Risk' || risk === 'High') highRiskCount++;
    else if (risk === 'Suspicious' || risk === 'Medium') suspiciousCount++;
    else if (risk === 'Safe' || risk === 'Low') safeCount++;
  });

  return (
    <PageTransition>
      {/* Header & Connection Status */}
      <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/15 text-blue-400 rounded-xl border border-blue-500/30">
            <Mail className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">Gmail Security Center</h1>
            <p className="text-xs text-slate-400">Read-only OAuth inbox inspection console for phishing & malicious link detection.</p>
          </div>
        </div>

        {/* Status Indicator */}
        {status && (
          <div className="flex flex-wrap items-center gap-3">
            {status.connected ? (
              <>
                {status.email_address && (
                  <div className="px-3 py-1.5 bg-slate-900/90 border border-slate-700/80 rounded-xl text-xs font-mono text-slate-300 flex items-center gap-2">
                    <span className="text-slate-500 font-semibold">Account:</span>
                    <span className="text-blue-400 font-semibold">{status.email_address}</span>
                  </div>
                )}
                <span className="px-3.5 py-1.5 bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 rounded-full text-xs font-mono font-semibold flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  Gmail Connected
                </span>
                <button
                  onClick={handleConnect}
                  disabled={loading}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition"
                  title="Re-run OAuth login"
                >
                  Reconnect
                </button>
                <button
                  onClick={handleDisconnect}
                  disabled={disconnecting}
                  className="px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl text-xs font-semibold transition flex items-center gap-1.5"
                  title="Disconnect and revoke Gmail access"
                >
                  {disconnecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <LogOut className="w-3.5 h-3.5" />}
                  Disconnect
                </button>
              </>
            ) : status.reauth_required ? (
              <>
                <span className="px-3.5 py-1.5 bg-amber-500/15 text-amber-400 border border-amber-500/30 rounded-full text-xs font-mono font-semibold flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                  Authorization Expired
                </span>
                <button
                  onClick={handleConnect}
                  disabled={loading}
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition shadow-lg shadow-amber-950/40"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                  Reconnect Gmail
                </button>
              </>
            ) : (
              <>
                <span className="px-3.5 py-1.5 bg-red-500/15 text-red-400 border border-red-500/30 rounded-full text-xs font-mono font-semibold flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-400 animate-ping" />
                  Authorization Required
                </span>
                <button
                  onClick={handleConnect}
                  disabled={loading}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition shadow-lg shadow-blue-950/40"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Mail className="w-4 h-4" />}
                  {status.token_exists ? 'Reconnect Gmail' : 'Connect Gmail'}
                </button>
              </>
            )}
          </div>
        )}

        {error && (
          <div className="w-full p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400 flex items-center justify-between">
            <span>{error}</span>
            <button
              onClick={() => setError('')}
              className="ml-3 text-red-400 hover:text-red-200 font-bold"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Stats row */}
      {status?.connected && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-[#0b1528] p-5 rounded-2xl border border-slate-800/80">
            <span className="text-xs font-mono text-slate-400 uppercase">Emails Scanned</span>
            <p className="text-2xl font-extrabold text-white font-mono mt-1">{fetchedCount}</p>
          </div>
          <div className="bg-[#0b1528] p-5 rounded-2xl border border-slate-800/80">
            <span className="text-xs font-mono text-emerald-400 uppercase">Safe Verified</span>
            <p className="text-2xl font-extrabold text-emerald-400 font-mono mt-1">{safeCount}</p>
          </div>
          <div className="bg-[#0b1329] p-5 rounded-2xl border border-slate-800/80">
            <span className="text-xs font-mono text-amber-400 uppercase">Suspicious Flagged</span>
            <p className="text-2xl font-extrabold text-amber-400 font-mono mt-1">{suspiciousCount}</p>
          </div>
          <div className="bg-[#0b1528] p-5 rounded-2xl border border-slate-800/80">
            <span className="text-xs font-mono text-red-400 uppercase">High Risk Phishing</span>
            <p className="text-2xl font-extrabold text-red-400 font-mono mt-1">{highRiskCount}</p>
          </div>
        </div>
      )}

      {/* Control Actions Row */}
      {status?.connected && (
        <div className="bg-[#0b1528] p-5 rounded-2xl border border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div>
              <label className="block text-[11px] font-mono font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Inbox Scan Limit
              </label>
              <input
                type="number"
                min={1}
                max={50}
                value={scanLimit}
                onChange={(e) => setScanLimit(Number(e.target.value))}
                className="w-24 px-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded-xl text-xs font-mono font-semibold text-slate-200"
              />
            </div>
            <button
              onClick={() => handleLoadMessages()}
              disabled={loading}
              className="mt-4 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-semibold flex items-center gap-2 transition"
            >
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
              Load Recent Emails
            </button>
          </div>

          {messages.length > 0 && (
            <button
              onClick={handleBatchScan}
              disabled={batchScanning}
              className="mt-4 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition shadow-lg shadow-blue-950/50"
            >
              {batchScanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldAlert className="w-4 h-4" />}
              Analyze Recent Emails
            </button>
          )}
        </div>
      )}

      {/* Security Inbox Table */}
      {messages.length > 0 ? (
        <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <h3 className="font-bold text-base text-white">Gmail Threat Security Table</h3>
          <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
            <table className="w-full text-xs text-left text-slate-300">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-mono tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Sender</th>
                  <th className="p-3">Subject</th>
                  <th className="p-3">Date</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Score</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                {messages.map((m) => {
                  const evt = analysisResults[m.message_id];
                  const assessment = evt?.assessment;
                  const riskLevel = assessment?.risk_level || 'Unscanned';
                  const score = assessment?.risk_score;

                  return (
                    <tr key={m.message_id} className="hover:bg-slate-900/50 transition">
                      <td className="p-3 font-mono text-slate-200 max-w-xs truncate">{m.sender}</td>
                      <td className="p-3 text-slate-300 max-w-sm truncate">{m.subject || '(no subject)'}</td>
                      <td className="p-3 font-mono text-slate-400 whitespace-nowrap">{m.received_timestamp || 'Unknown'}</td>
                      <td className="p-3"><ThreatBadge risk={riskLevel} size="sm" /></td>
                      <td className="p-3 font-mono font-bold">{score !== undefined ? `${score.toFixed(1)}/10` : '-'}</td>
                      <td className="p-3 text-right">
                        {evt ? (
                          <button
                            onClick={() => setSelectedThreat({
                              input: `Gmail: ${m.subject} (From: ${m.sender})`,
                              ...evt.assessment,
                            })}
                            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-semibold transition"
                          >
                            View Analysis
                          </button>
                        ) : (
                          <button
                            onClick={() => handleScanSingleMessage(m.message_id)}
                            disabled={analyzingId === m.message_id || batchScanning}
                            className="px-3 py-1 bg-blue-600/80 hover:bg-blue-600 disabled:opacity-50 text-white rounded-lg text-[11px] font-semibold transition inline-flex items-center gap-1.5"
                          >
                            {analyzingId === m.message_id ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              <ShieldAlert className="w-3 h-3" />
                            )}
                            Scan
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : loading ? (
        <div className="p-12 text-center bg-[#0b1528] border border-slate-800/80 rounded-2xl text-slate-400 space-y-3">
          <Loader2 className="w-10 h-10 text-blue-400 animate-spin mx-auto" />
          <p className="text-sm font-semibold text-slate-300">Retrieving Gmail Messages...</p>
          <p className="text-xs text-slate-500">Connecting to Gmail API to load recent inbox emails for threat inspection.</p>
        </div>
      ) : (
        status?.connected && (
          <div className="p-12 text-center bg-[#0b1528] border border-slate-800/80 rounded-2xl text-slate-400 space-y-3">
            <Inbox className="w-10 h-10 text-slate-500 mx-auto" />
            <p className="text-sm font-semibold text-slate-300">No Emails Loaded</p>
            <p className="text-xs text-slate-500">Click 'Load Recent Emails' to retrieve inbox messages for threat scanning.</p>
          </div>
        )
      )}

      {/* Modals */}
      {selectedThreat && (
        <ThreatDetailsModal
          item={selectedThreat}
          onClose={() => setSelectedThreat(null)}
          onAskGemini={(item) => {
            setSelectedThreat(null);
            setGeminiTarget(item);
          }}
        />
      )}

      {geminiTarget && (
        <GeminiModal
          detection={geminiTarget}
          onClose={() => setGeminiTarget(null)}
        />
      )}
    </PageTransition>
  );
};

export default GmailSecurity;
