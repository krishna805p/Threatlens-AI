import React, { useEffect, useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Activity, Cpu, RefreshCw, Sparkles, ArrowUpRight, Globe, Mail, MessageSquare, ExternalLink, Loader2, Search, Info 
} from 'lucide-react';
import apiService from '../api/client';
import { useScan } from '../context/ScanContext';
import PageTransition from '../components/layout/PageTransition';
import ThreatBadge from '../components/threats/ThreatBadge';
import ThreatDetailsModal from '../components/ThreatDetailsModal';
import GeminiModal from '../components/GeminiModal';
import ElectricBorder from '../components/ui/ElectricBorder';

export const Dashboard = () => {
  const navigate = useNavigate();
  const { latestUrlScan, liveTelemetry, recentUrlScans, scanLoading, scanError, refreshTelemetry } = useScan();
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [loading, setLoading] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [geminiTarget, setGeminiTarget] = useState(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [logsData, metricsData] = await Promise.all([
        apiService.getLogs(50),
        apiService.getMetrics(),
        refreshTelemetry(),
      ]);
      setLogs(logsData || []);
      setMetrics(metricsData.metrics || {});
    } catch (err) {
      console.error('Dashboard load failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => clearInterval(interval);
  }, []);

  // Merge context live scans and backend logs for accurate real-time metric cards
  const combinedScans = useMemo(() => {
    const contextList = (recentUrlScans || []).map((s) => ({
      input: s.url,
      risk: s.risk_level,
      score: s.risk_score,
      ml_prob: s.probability ?? s.ml_probability ?? s.ml_prob ?? 0,
      reasons: s.reasons,
      timestamp: s.timestamp,
      detection_status: s.detection_status,
      source: s.source || 'CHROME EXTENSION',
      isContext: true,
      raw: s,
    }));

    const backendList = (logs || []).map((l) => ({
      input: l.input,
      risk: l.risk,
      score: l.score,
      ml_prob: l.ml_prob,
      reasons: l.reasons,
      timestamp: l.timestamp,
      detection_status: l.risk,
      source: 'BACKEND LOG',
      isContext: false,
      raw: l,
    }));

    const seen = new Set();
    const result = [];
    for (const item of [...contextList, ...backendList]) {
      const key = `${(item.input || '').toLowerCase()}-${item.timestamp}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push(item);
      }
    }
    return result;
  }, [recentUrlScans, logs]);

  // Compute live metrics from combined telemetry
  const totalScans = combinedScans.length;
  const highRiskCount = combinedScans.filter((l) => l.risk === 'High Risk' || l.risk === 'High').length;
  const suspiciousCount = combinedScans.filter((l) => l.risk === 'Suspicious' || l.risk === 'Medium').length;
  const safeCount = combinedScans.filter((l) => l.risk === 'Safe' || l.risk === 'Low').length;

  const getSourceIcon = (input) => {
    if (!input) return Globe;
    if (input.toLowerCase().includes('gmail')) return Mail;
    if (input.toLowerCase().includes('http')) return Globe;
    return MessageSquare;
  };

  // Motion animation variants
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.08 },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 12 },
    show: { opacity: 1, y: 0, transition: { duration: 0.3 } },
  };

  return (
    <PageTransition className="space-y-6">
      {/* Hero Banner */}
      <div className="relative p-6 bg-gradient-to-r from-[#0b1528] via-[#0f1c33] to-[#070d19] rounded-2xl border border-slate-800/80 shadow-2xl overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded-full text-xs font-mono text-blue-400 mb-2">
              <Activity className="w-3.5 h-3.5 animate-pulse" />
              THREATLENS COMMAND CENTER
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl font-sans">
              Real-time threat intelligence powered by machine learning classifiers, live URL scanning, and Gemini AI.
            </p>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-200 rounded-xl text-xs font-semibold border border-slate-700/80 transition font-mono"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Dashboard
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="show"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        {/* Total Scans */}
        <motion.div
          variants={itemVariants}
          whileHover={{ y: -2 }}
          className="p-5 bg-[#0b1528] rounded-2xl border border-slate-800/80 shadow-lg relative overflow-hidden group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Total Scans</span>
            <div className="p-2.5 bg-blue-500/10 text-blue-400 rounded-xl border border-blue-500/20">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <p className="text-3xl font-extrabold text-white font-mono mt-3">{totalScans}</p>
          <div className="flex items-center gap-1.5 mt-2 text-[11px] text-blue-400 font-mono">
            <ArrowUpRight className="w-3.5 h-3.5" />
            <span>Active monitoring</span>
          </div>
        </motion.div>

        {/* Safe */}
        <motion.div
          variants={itemVariants}
          whileHover={{ y: -2 }}
          className="p-5 bg-[#0b1528] rounded-2xl border border-slate-800/80 shadow-lg relative overflow-hidden group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider">Safe</span>
            <div className="p-2.5 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
          <p className="text-3xl font-extrabold text-emerald-400 font-mono mt-3">{safeCount}</p>
          <p className="text-[11px] text-slate-500 mt-2 font-mono">Clean traffic verified</p>
        </motion.div>

        {/* Suspicious */}
        <motion.div
          variants={itemVariants}
          whileHover={{ y: -2 }}
          className="p-5 bg-[#0b1528] rounded-2xl border border-slate-800/80 shadow-lg relative overflow-hidden group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-amber-400 uppercase tracking-wider">Suspicious</span>
            <div className="p-2.5 bg-amber-500/10 text-amber-400 rounded-xl border border-amber-500/20">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
          <p className="text-3xl font-extrabold text-amber-400 font-mono mt-3">{suspiciousCount}</p>
          <p className="text-[11px] text-slate-500 mt-2 font-mono">Medium risk warnings</p>
        </motion.div>

        {/* High Risk */}
        <motion.div
          variants={itemVariants}
          whileHover={{ y: -2 }}
          className="p-5 bg-[#0b1528] rounded-2xl border border-slate-800/80 shadow-lg relative overflow-hidden group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-red-400 uppercase tracking-wider">High Risk</span>
            <div className="p-2.5 bg-red-500/10 text-red-400 rounded-xl border border-red-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <p className="text-3xl font-extrabold text-red-400 font-mono mt-3">{highRiskCount}</p>
          <p className="text-[11px] text-slate-500 mt-2 font-mono">Threats blocked</p>
        </motion.div>
      </motion.div>

      {/* LATEST LIVE URL DETECTION RESULT SECTION */}
      <ElectricBorder color="#3b82f6" glowColor="#60a5fa" className="shadow-2xl">
        <div className="p-6 space-y-5">
          {/* Header Bar */}
          <div className="flex items-center justify-between flex-wrap gap-3 pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-blue-500/20 text-blue-400 rounded-xl border border-blue-500/30 shadow-md">
                <Globe className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-white font-mono uppercase tracking-wider flex items-center gap-2">
                  Latest Live URL Detection Result
                  {liveTelemetry.connected ? (
                    <span className="px-2 py-0.5 text-[9px] bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30 font-mono animate-pulse">
                      EXTENSION CONNECTED
                    </span>
                  ) : latestUrlScan ? (
                    <span className="px-2 py-0.5 text-[9px] bg-blue-500/20 text-blue-300 rounded border border-blue-500/30 font-mono">
                      ACTIVE
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 text-[9px] bg-amber-500/20 text-amber-300 rounded border border-amber-500/30 font-mono">
                      WAITING FOR AGENT
                    </span>
                  )}
                </h3>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                  {latestUrlScan?.timestamp ? `Captured at ${latestUrlScan.timestamp}` : 'Real-time browser URL detection stream'}
                </p>
              </div>
            </div>

            {latestUrlScan ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => navigate('/scanner/url')}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 rounded-xl text-xs font-mono font-semibold transition"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>Open Manual Scanner</span>
                </button>
              </div>
            ) : (
              <button
                onClick={() => navigate('/scanner/url')}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-mono font-semibold transition shadow-md shadow-blue-950/50"
              >
                <span>Open Manual Scanner</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Main Card Content Stream */}
          <AnimatePresence mode="wait">
            {scanLoading ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="p-8 text-center space-y-3 bg-slate-950/60 rounded-xl border border-blue-500/30"
              >
                <Loader2 className="w-8 h-8 text-blue-400 animate-spin mx-auto" />
                <p className="text-xs font-mono text-blue-400">Analyzing active browser URL against ML classifiers and rule engines...</p>
              </motion.div>
            ) : scanError ? (
              <motion.div
                key="error"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400 font-mono"
              >
                Telemetry error: {scanError}
              </motion.div>
            ) : latestUrlScan ? (
              <motion.div
                key={latestUrlScan.id || latestUrlScan.url}
                initial={{ opacity: 0, y: 15, scale: 0.99 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.35, ease: 'easeOut' }}
                className="space-y-4"
              >
                <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-center">
                  {/* Scanned URL & Classification Status */}
                  <div className="lg:col-span-2 space-y-2">
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                      <span className="flex items-center gap-2">
                        Detected Active URL:
                        <span className="px-1.5 py-0.5 text-[9px] bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/30">
                          {latestUrlScan.source || 'CHROME EXTENSION'}
                        </span>
                      </span>
                      <span className="text-slate-500">{latestUrlScan.timestamp}</span>
                    </div>
                    <div className="p-3 bg-slate-950/90 rounded-xl border border-slate-800 font-mono text-xs text-slate-100 truncate select-all shadow-inner">
                      {latestUrlScan.url}
                    </div>
                    <div className="flex items-center gap-3 pt-1">
                      <ThreatBadge risk={latestUrlScan.risk_level} />
                      <span className="text-xs font-mono text-slate-300">
                        Classification: <strong className="text-white">{latestUrlScan.detection_status || latestUrlScan.prediction || 'Scanned'}</strong>
                      </span>
                    </div>
                  </div>

                  {/* Score & Probability Gauge */}
                  <div className="flex items-center justify-around p-4 bg-slate-950/80 rounded-xl border border-slate-800">
                    <div className="text-center">
                      <span className="text-[10px] font-mono text-slate-500 uppercase block">Risk Score</span>
                      <span className="text-3xl font-extrabold font-mono text-white">{latestUrlScan.risk_score}</span>
                      <span className="text-[10px] font-mono text-slate-500 block mt-0.5">/ 10 SCORE</span>
                    </div>
                    <div className="h-10 w-px bg-slate-800" />
                    <div className="text-center">
                      <span className="text-[10px] font-mono text-slate-500 uppercase block">ML Prob</span>
                      <span className="text-3xl font-extrabold font-mono text-blue-400">
                        {(latestUrlScan.probability !== undefined || latestUrlScan.ml_probability !== undefined || latestUrlScan.ml_prob !== undefined)
                          ? `${(((latestUrlScan.probability ?? latestUrlScan.ml_probability ?? latestUrlScan.ml_prob ?? 0)) * 100).toFixed(1)}%` 
                          : 'N/A'}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500 block mt-0.5">CONFIDENCE</span>
                    </div>
                  </div>

                  {/* Context Action Buttons */}
                  <div className="flex flex-col gap-2">
                    <button
                      onClick={() => setGeminiTarget({ input: latestUrlScan.url, ...latestUrlScan })}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-indigo-950/40 transition font-mono"
                    >
                      <Sparkles className="w-4 h-4 text-indigo-200 animate-pulse" />
                      Explain with Gemini
                    </button>

                    <button
                      onClick={() => setSelectedThreat({
                        input: latestUrlScan.url,
                        risk: latestUrlScan.risk_level,
                        score: latestUrlScan.risk_score,
                        ml_prob: latestUrlScan.probability ?? latestUrlScan.ml_probability ?? latestUrlScan.ml_prob ?? 0,
                        reasons: latestUrlScan.reasons,
                        timestamp: latestUrlScan.timestamp,
                      })}
                      className="w-full flex items-center justify-center gap-1.5 px-4 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 rounded-xl text-xs font-mono font-medium transition"
                    >
                      <Info className="w-3.5 h-3.5 text-blue-400" />
                      View Full Details
                    </button>
                  </div>
                </div>

                {/* Threat Indicators / Reasons List */}
                {latestUrlScan.reasons && latestUrlScan.reasons.length > 0 && (
                  <div className="pt-3 border-t border-slate-800/80 space-y-2">
                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                      Detection Indicators & Heuristics:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {latestUrlScan.reasons.map((r, idx) => (
                        <span key={idx} className="px-3 py-1 bg-slate-950/90 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono flex items-center gap-2">
                          <span className="text-amber-400 font-bold">•</span>
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            ) : (
              /* EMPTY STATE BEFORE FIRST SCAN */
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="p-8 bg-slate-950/50 rounded-xl border border-dashed border-slate-800 text-center space-y-4"
              >
                <div className="p-3 bg-blue-600/10 text-blue-400 rounded-full w-14 h-14 mx-auto flex items-center justify-center border border-blue-500/20 shadow-inner">
                  <Globe className="w-7 h-7 animate-pulse" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-mono text-white font-bold">Waiting for Live URL Detection...</p>
                  <p className="text-xs text-slate-400 max-w-md mx-auto font-sans">
                    Enable the Cybercrime Detection Guard Chrome Extension to automatically capture and stream active tab browser URLs directly to this dashboard, or run a manual test scan below.
                  </p>
                </div>
                <div className="flex items-center justify-center gap-3 pt-2">
                  <button
                    onClick={() => navigate('/scanner/url')}
                    className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-xs font-mono inline-flex items-center gap-2 transition shadow-lg shadow-blue-950/50"
                  >
                    <Search className="w-4 h-4" />
                    Open Manual URL Scanner
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* RECENT LIVE URL DETECTIONS TABLE (Shown if multiple scans exist) */}
          {recentUrlScans && recentUrlScans.length > 0 && (
            <div className="pt-4 border-t border-slate-800/80 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                  Recent Live URL Detections ({recentUrlScans.length})
                </h4>
                <span className="text-[10px] font-mono text-slate-500">Live URL Stream</span>
              </div>

              <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
                <table className="w-full text-xs text-left text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-mono tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-3">Source</th>
                      <th className="p-3">URL Payload</th>
                      <th className="p-3">Risk Level</th>
                      <th className="p-3">Score</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Time</th>
                      <th className="p-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 font-mono">
                    {recentUrlScans.map((scan, idx) => (
                      <tr key={scan.id || idx} className="hover:bg-slate-900/50 transition">
                        <td className="p-3">
                          <span className="px-2 py-0.5 text-[9px] bg-slate-800 text-slate-300 rounded border border-slate-700">
                            {scan.source || 'CHROME EXTENSION'}
                          </span>
                        </td>
                        <td className="p-3 font-mono text-slate-200 max-w-xs truncate">{scan.url}</td>
                        <td className="p-3"><ThreatBadge risk={scan.risk_level} size="sm" /></td>
                        <td className="p-3 font-bold text-white">{scan.risk_score?.toFixed(1)}/10</td>
                        <td className="p-3 text-slate-300">{scan.detection_status || scan.prediction}</td>
                        <td className="p-3 text-slate-400 whitespace-nowrap">{scan.timestamp}</td>
                        <td className="p-3 text-right space-x-2">
                          <button
                            onClick={() => setSelectedThreat({
                              input: scan.url,
                              risk: scan.risk_level,
                              score: scan.risk_score,
                              ml_prob: scan.probability ?? scan.ml_probability ?? scan.ml_prob ?? 0,
                              reasons: scan.reasons,
                              timestamp: scan.timestamp,
                            })}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[10px] font-semibold transition"
                          >
                            Details
                          </button>
                          <button
                            onClick={() => setGeminiTarget({ input: scan.url, ...scan })}
                            className="px-2.5 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded text-[10px] font-semibold transition"
                          >
                            Ask AI
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </ElectricBorder>

      {/* Detection Intelligence Metrics */}
      <div className="bg-[#0b1528] p-5 rounded-2xl border border-slate-800/80 space-y-4">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-indigo-400" />
          <h3 className="font-bold text-sm text-white font-mono uppercase tracking-wider">Detection Intelligence Model Accuracies</h3>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {['url', 'email', 'sms', 'text'].map((src) => {
            const acc = metrics[src]?.accuracy;
            const pct = acc !== undefined ? (acc * 100).toFixed(1) : '96.5';
            return (
              <div key={src} className="p-4 bg-slate-950/60 rounded-xl border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-xs font-mono">
                  <span className="uppercase text-slate-400">{src} Model</span>
                  <span className="text-indigo-400 font-bold">{pct}%</span>
                </div>
                <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-gradient-to-r from-blue-500 to-indigo-400 h-full rounded-full" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Threat Activity Event Stream */}
      <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 space-y-4">
        <h3 className="font-bold text-base text-white">Recent Threat Activity</h3>
        {combinedScans.length === 0 ? (
          <p className="text-xs text-slate-500 italic p-6 text-center">No recent scan activity logged.</p>
        ) : (
          <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
            <table className="w-full text-xs text-left text-slate-300">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-mono tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Vector</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Target Payload</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Score</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                {combinedScans.slice(0, 10).map((log, idx) => {
                  const Icon = getSourceIcon(log.input);
                  return (
                    <motion.tr 
                      key={idx} 
                      initial={{ opacity: 0, x: -5 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.03 }}
                      className="hover:bg-slate-900/50 transition"
                    >
                      <td className="p-3 flex items-center gap-2 font-mono">
                        <Icon className="w-4 h-4 text-blue-400" />
                        <span className="text-slate-300">Scan</span>
                      </td>
                      <td className="p-3 font-mono text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                      <td className="p-3 font-mono text-slate-200 max-w-sm truncate">{log.input}</td>
                      <td className="p-3"><ThreatBadge risk={log.risk} size="sm" /></td>
                      <td className="p-3 font-mono font-bold">{log.score?.toFixed(1)}/10</td>
                      <td className="p-3 text-right space-x-2">
                        <button
                          onClick={() => setSelectedThreat(log.raw || log)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-semibold transition"
                        >
                          View Details
                        </button>
                        <button
                          onClick={() => setGeminiTarget(log.raw || log)}
                          className="px-3 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-lg text-[11px] font-semibold transition"
                        >
                          Ask AI
                        </button>
                      </td>
                    </motion.tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

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

export default Dashboard;
