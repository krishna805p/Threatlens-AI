import React from 'react';
import { X, ShieldAlert, Sparkles, Link2, FileText, AlertTriangle } from 'lucide-react';
import RiskBadge from './RiskBadge';

export const ThreatDetailsModal = ({ item, onClose, onAskGemini }) => {
  if (!item) return null;

  const riskLevel = item.risk_level || item.risk || 'Unknown';
  const riskScore = item.risk_score ?? item.score ?? 0;
  const probability = item.probability ?? item.ml_probability ?? item.ml_prob ?? 0;
  const reasons = item.reasons || item.reason || [];
  const debug = item.debug || item.metadata || {};
  const urls = debug.urls || [];
  const nlp = debug.nlp || debug.nlp_detector || {};

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="bg-[#0b1528] border border-slate-700/80 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl shadow-blue-950/50">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-[#0b1528] z-10">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 text-blue-400 rounded-xl border border-blue-500/20">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-lg text-white">Security Threat Inspection</h3>
              <p className="text-xs text-slate-400">Detailed Detection & Explainability Analysis</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Key Metrics Row */}
          <div className="grid grid-cols-3 gap-4 p-4 bg-slate-900/80 rounded-xl border border-slate-800">
            <div>
              <p className="text-xs text-slate-400 font-medium">Risk Level</p>
              <div className="mt-1">
                <RiskBadge risk={riskLevel} />
              </div>
            </div>
            <div>
              <p className="text-xs text-slate-400 font-medium">Risk Score</p>
              <p className="text-lg font-bold text-slate-100 mt-1">
                {typeof riskScore === 'number' ? riskScore.toFixed(1) : riskScore}/10
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-400 font-medium">ML Probability</p>
              <p className="text-lg font-bold text-blue-400 mt-1">
                {(probability * (probability <= 1 ? 100 : 1)).toFixed(1)}%
              </p>
            </div>
          </div>

          {/* Input content snippet */}
          {item.input && (
            <div>
              <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">Target Content</p>
              <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 text-sm font-mono text-slate-300 break-all">
                {item.input}
              </div>
            </div>
          )}

          {/* Reasons */}
          {reasons.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Detection Reasons
              </p>
              <ul className="space-y-2">
                {reasons.map((r, i) => (
                  <li key={i} className="p-2.5 bg-slate-900/50 rounded-lg border border-slate-800 text-xs text-slate-300 flex items-start gap-2">
                    <span className="text-amber-400 font-bold">•</span>
                    <span>{typeof r === 'object' ? r.reason || JSON.stringify(r) : r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* NLP Analysis */}
          {nlp.detected_patterns && nlp.detected_patterns.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-blue-400" />
                NLP Pattern Findings
              </p>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 text-xs space-y-1">
                <p className="text-slate-300">
                  <span className="text-slate-400">Scam Probability: </span>
                  <span className="font-semibold text-blue-400">{(nlp.scam_probability * 100).toFixed(1)}%</span>
                </p>
                <p className="text-slate-300">
                  <span className="text-slate-400">Triggers: </span>
                  <span className="font-mono text-amber-300">{nlp.detected_patterns.join(', ')}</span>
                </p>
              </div>
            </div>
          )}

          {/* Extracted URLs Table */}
          {urls.length > 0 && (
            <div>
              <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Link2 className="w-4 h-4 text-indigo-400" />
                Extracted URLs & Reputation Breakdown
              </p>
              <div className="overflow-x-auto border border-slate-800 rounded-xl">
                <table className="w-full text-xs text-left text-slate-300">
                  <thead className="bg-slate-900 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">URL</th>
                      <th className="p-2.5">Risk Level</th>
                      <th className="p-2.5">Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                    {urls.map((u, idx) => (
                      <tr key={idx}>
                        <td className="p-2.5 font-mono text-[11px] break-all max-w-xs">{u.url}</td>
                        <td className="p-2.5"><RiskBadge risk={u.risk_level} size="sm" /></td>
                        <td className="p-2.5 font-semibold">{u.risk_score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between bg-slate-900/50">
          {onAskGemini && (
            <button
              onClick={() => onAskGemini(item)}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-xl text-xs font-semibold transition"
            >
              <Sparkles className="w-4 h-4 text-indigo-400" />
              Ask AI Security Assistant
            </button>
          )}
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition ml-auto"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ThreatDetailsModal;
