import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquareText, Loader2, Sparkles, AlertTriangle, FileText, Zap } from 'lucide-react';
import apiService from '../api/client';
import PageTransition from '../components/layout/PageTransition';
import ThreatBadge from '../components/threats/ThreatBadge';
import GeminiModal from '../components/GeminiModal';

export const TextScanner = () => {
  const [source, setSource] = useState('text');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [geminiTarget, setGeminiTarget] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!content.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await apiService.analyze(source, content.trim());
      setResult(data);

      try {
        await apiService.logEvent({
          input: content.trim().substring(0, 80),
          risk: data.risk_level,
          score: data.risk_score,
          ml_prob: data.probability ?? data.ml_probability ?? data.ml_prob ?? 0,
          reasons: data.reasons || [],
        });
      } catch (logErr) {
        console.warn('Logging skipped:', logErr);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Text analysis failed. Verify backend API connection.');
    } finally {
      setLoading(false);
    }
  };

  // Function to highlight suspicious words in original text
  const renderHighlightedText = (text) => {
    if (!text) return null;
    const suspiciousWords = ['locked', 'verify', 'immediately', 'bank', 'otp', 'password', 'account', 'urgent', 'http://', 'https://'];
    const parts = text.split(/(\s+)/);

    return parts.map((part, idx) => {
      const lower = part.toLowerCase();
      const isMatch = suspiciousWords.some((word) => lower.includes(word));
      if (isMatch) {
        return (
          <span key={idx} className="bg-amber-500/20 text-amber-300 font-bold px-1 rounded border border-amber-500/30">
            {part}
          </span>
        );
      }
      return <span key={idx}>{part}</span>;
    });
  };

  return (
    <PageTransition>
      {/* Header */}
      <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 shadow-xl space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/15 text-blue-400 rounded-xl border border-blue-500/30">
            <MessageSquareText className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">Message Threat Analyzer</h1>
            <p className="text-xs text-slate-400">NLP scam pattern recognition, urgency heuristic rules, and credential harvesting detection.</p>
          </div>
        </div>

        {/* Editor Workspace */}
        <form onSubmit={handleScan} className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex gap-2">
              {['text', 'sms', 'email'].map((src) => (
                <button
                  key={src}
                  type="button"
                  onClick={() => setSource(src)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition ${
                    source === src
                      ? 'bg-blue-600 text-white shadow-md shadow-blue-950/40'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {src} Vector
                </button>
              ))}
            </div>
            <span className="text-xs font-mono text-slate-500">{content.length} chars | {content.split(/\s+/).filter(Boolean).length} words</span>
          </div>

          <textarea
            rows={5}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Paste suspicious SMS, raw email text, or message snippet here (e.g. 'Urgent! Your account will be LOCKED within 24 hours. Verify password immediately at http://login-check.com')"
            className="w-full p-4 bg-slate-950 border border-slate-700/80 rounded-xl text-sm font-sans text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition"
          />

          <button
            type="submit"
            disabled={loading || !content.trim()}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-xl text-xs flex items-center gap-2 transition shadow-lg shadow-blue-950/50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            Analyze Message Threat
          </button>
        </form>

        {error && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400">
            {error}
          </div>
        )}
      </div>

      {/* Result Display Workspace */}
      {result && (
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 lg:grid-cols-2 gap-6"
        >
          {/* LEFT: Highlighted Original Text */}
          <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <FileText className="w-4 h-4 text-blue-400" />
              Semantic Pattern Highlighting
            </h3>
            <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 text-sm text-slate-200 leading-relaxed font-sans min-h-[160px]">
              {renderHighlightedText(content)}
            </div>
            <p className="text-[11px] text-slate-500 font-mono">
              Highlighted phrases indicate detected urgency cues, financial lures, or credential harvesting triggers.
            </p>
          </div>

          {/* RIGHT: Threat Analysis Findings */}
          <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-6">
            <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-400 font-mono">Classification</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xl font-bold text-white">{result.prediction}</span>
                  <ThreatBadge risk={result.risk_level} />
                </div>
              </div>
              <div className="text-right font-mono">
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className="text-xl font-bold text-blue-400 mt-1">{result.risk_score}/10</p>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Detection Reasons
              </h4>
              <div className="space-y-2">
                {result.reasons?.map((reason, idx) => (
                  <div key={idx} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5">
                    <span className="text-amber-400 font-bold">•</span>
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Pattern Triggers */}
            {result.debug?.nlp_detector?.detected_patterns && (
              <div>
                <p className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">NLP Pattern Identifiers</p>
                <div className="flex flex-wrap gap-2">
                  {result.debug.nlp_detector.detected_patterns.map((p, idx) => (
                    <span key={idx} className="px-2.5 py-1 bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 rounded-lg text-xs font-mono">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setGeminiTarget({ input: content, ...result })}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-xl text-xs font-semibold transition"
              >
                <Sparkles className="w-4 h-4 text-indigo-400" />
                Explain with AI
              </button>
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

export default TextScanner;
