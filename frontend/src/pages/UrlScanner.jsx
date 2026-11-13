import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Search, Loader2, Sparkles, AlertTriangle, ShieldCheck, CheckCircle2, Lock, Sliders, Server } from 'lucide-react';
import apiService from '../api/client';
import { useScan } from '../context/ScanContext';
import PageTransition from '../components/layout/PageTransition';
import ThreatBadge from '../components/threats/ThreatBadge';
import GeminiModal from '../components/GeminiModal';

export const UrlScanner = () => {
  const { addUrlScan, setScanLoading, setScanError } = useScan();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [fpStatus, setFpStatus] = useState('');
  const [geminiTarget, setGeminiTarget] = useState(null);

  const steps = [
    'URL Normalization',
    'Feature Extraction (Entropy & Length)',
    'ML Random Forest Classifier',
    'NLP & Heuristic Rule Engine',
    'VirusTotal & Safe Browsing API Queries',
    'Final Risk Assessment',
  ];

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setScanLoading(true);
    setError('');
    setScanError('');
    setResult(null);
    setFpStatus('');

    // Animated scanning step sequence
    for (let i = 0; i < steps.length; i++) {
      setScanStep(steps[i]);
      await new Promise((r) => setTimeout(r, 200));
    }

    try {
      const data = await apiService.analyze('url', url.trim());
      setResult(data);
      addUrlScan(url.trim(), data);

      try {
        await apiService.logEvent({
          input: url.trim(),
          risk: data.risk_level,
          score: data.risk_score,
          ml_prob: data.probability ?? data.ml_probability ?? data.ml_prob ?? 0,
          reasons: data.reasons || [],
        });
      } catch (logErr) {
        console.warn('Logging skipped:', logErr);
      }
    } catch (err) {
      const errMsg = err.response?.data?.detail || 'URL analysis failed. Verify backend API connection.';
      setError(errMsg);
      setScanError(errMsg);
    } finally {
      setLoading(false);
      setScanLoading(false);
    }
  };

  const handleFalsePositive = async () => {
    if (!url.trim()) return;
    try {
      const res = await apiService.reportFalsePositive(url.trim());
      setFpStatus(res.message || `Added ${res.trusted_domain} to trusted domain whitelist.`);
      const updated = await apiService.analyze('url', url.trim());
      setResult(updated);
      addUrlScan(url.trim(), updated);
    } catch (err) {
      setFpStatus('Failed to add domain to trusted list.');
    }
  };

  const normRisk = result?.risk_level || 'Unknown';
  let glowColor = 'shadow-blue-950/40 border-slate-800';
  if (normRisk === 'High Risk' || normRisk === 'High') {
    glowColor = 'shadow-red-950/60 border-red-500/40 shadow-2xl';
  } else if (normRisk === 'Suspicious' || normRisk === 'Medium') {
    glowColor = 'shadow-amber-950/60 border-amber-500/40 shadow-2xl';
  } else if (normRisk === 'Safe' || normRisk === 'Low') {
    glowColor = 'shadow-emerald-950/60 border-emerald-500/40 shadow-2xl';
  }

  return (
    <PageTransition>
      {/* Header */}
      <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 shadow-xl space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/15 text-blue-400 rounded-xl border border-blue-500/30">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">URL Threat Scanner</h1>
            <p className="text-xs text-slate-400">Analyze suspicious URLs using ML detection, rule-based analysis and threat intelligence.</p>
          </div>
        </div>

        {/* Tactical Search Bar Input */}
        <form onSubmit={handleScan} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-4 top-3.5" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Paste URL to inspect (e.g. http://secure-login-payroll-check.com)"
              className="w-full pl-11 pr-4 py-3 bg-slate-950 border border-slate-700/80 rounded-xl text-sm text-slate-100 font-mono placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-xl text-xs flex items-center gap-2 transition shadow-lg shadow-blue-950/50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
            Analyze Threat
          </button>
        </form>

        {/* Animated Scanning Pipeline State */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="p-4 bg-slate-950/80 rounded-xl border border-blue-500/30 space-y-2"
            >
              <div className="flex items-center justify-between text-xs font-mono text-blue-400">
                <span className="flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ANALYZING PIPELINE STAGE:
                </span>
                <span className="font-bold">{scanStep}</span>
              </div>
              <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                <div className="bg-gradient-to-r from-blue-500 to-indigo-400 h-full w-full animate-pulse" />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400">
            {error}
          </div>
        )}
      </div>

      {/* Result Presentation */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          className={`bg-[#0b1528] p-6 rounded-2xl border transition-all duration-300 ${glowColor} space-y-6`}
        >
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Radial Risk Meter */}
            <div className="bg-slate-950/60 p-6 rounded-2xl border border-slate-800/80 flex flex-col justify-between items-center text-center">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">RISK SCORE METER</span>

              <div className="my-6 relative flex items-center justify-center">
                <div className="w-44 h-44 rounded-full border-8 border-slate-900 flex flex-col items-center justify-center relative bg-slate-950/80 shadow-inner">
                  <span className="text-5xl font-extrabold font-mono text-white">{result.risk_score}</span>
                  <span className="text-[10px] font-mono text-slate-500 uppercase mt-1">/ 10 SCORE</span>
                  <div className="mt-2">
                    <ThreatBadge risk={result.risk_level} />
                  </div>
                </div>
              </div>

              <div className="w-full p-3 bg-slate-900/80 rounded-xl border border-slate-800 text-xs text-slate-300 space-y-1">
                <p className="flex justify-between font-mono text-[11px]">
                  <span className="text-slate-400">Classification:</span>
                  <span className="font-bold text-slate-100">{result.prediction}</span>
                </p>
                <p className="flex justify-between font-mono text-[11px]">
                  <span className="text-slate-400">ML Probability:</span>
                  <span className="font-bold text-blue-400">{(((result.probability ?? result.ml_probability ?? result.ml_prob ?? 0)) * 100).toFixed(1)}%</span>
                </p>
              </div>
            </div>

            {/* Reasons & Technical Breakdown */}
            <div className="lg:col-span-2 space-y-6">
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  Detection Reasons & Explainability
                </h3>
                <div className="space-y-2">
                  {result.reasons?.map((reason, idx) => (
                    <div key={idx} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5">
                      <span className="text-amber-400 font-bold">•</span>
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Debug / Reputation Info */}
              {result.debug && (
                <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800/80 text-xs space-y-2 font-mono">
                  <p className="font-semibold text-slate-300">Reputation & API Verdicts</p>
                  {result.debug.api_result && (
                    <p className="text-slate-400">
                      API Verdict: <span className="text-blue-400 font-bold">{result.debug.api_result.verdict}</span> (Confidence: {(result.debug.api_result.confidence_score * 100).toFixed(0)}%)
                    </p>
                  )}
                  {result.debug.rule_triggers && result.debug.rule_triggers.length > 0 && (
                    <div>
                      <p className="text-slate-400 mb-1">Rule Triggers:</p>
                      <ul className="list-disc pl-4 text-amber-300 space-y-0.5">
                        {result.debug.rule_triggers.map((t, idx) => (
                          <li key={idx}>{t.reason || t.rule_name}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Actions Bar */}
              <div className="flex items-center justify-between pt-4 border-t border-slate-800">
                <button
                  onClick={handleFalsePositive}
                  className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-emerald-400 transition"
                >
                  <ShieldCheck className="w-4 h-4" />
                  Report False Positive
                </button>

                <button
                  onClick={() => setGeminiTarget({ input: url, ...result })}
                  className="flex items-center gap-2 px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-xl text-xs font-semibold transition"
                >
                  <Sparkles className="w-4 h-4 text-indigo-400" />
                  Explain with AI
                </button>
              </div>

              {fpStatus && (
                <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-xs text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  {fpStatus}
                </div>
              )}
            </div>
          </div>
        </motion.div>
      )}

      {/* Gemini AI Assistant Modal */}
      {geminiTarget && (
        <GeminiModal
          detection={geminiTarget}
          onClose={() => setGeminiTarget(null)}
        />
      )}
    </PageTransition>
  );
};

export default UrlScanner;
