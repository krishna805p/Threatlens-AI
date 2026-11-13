import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { History as HistoryIcon, Search, Filter, RefreshCw, Terminal } from 'lucide-react';
import apiService from '../api/client';
import PageTransition from '../components/layout/PageTransition';
import ThreatBadge from '../components/threats/ThreatBadge';
import ThreatDetailsModal from '../components/ThreatDetailsModal';
import GeminiModal from '../components/GeminiModal';

export const History = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRisk, setSelectedRisk] = useState('All');
  const [selectedVector, setSelectedVector] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [geminiTarget, setGeminiTarget] = useState(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await apiService.getLogs(100, selectedRisk);
      setLogs(data || []);
    } catch (err) {
      console.error('Failed to fetch scan logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [selectedRisk]);

  const filteredLogs = logs.filter((l) => {
    if (selectedVector !== 'All') {
      const inputLower = (l.input || '').toLowerCase();
      if (selectedVector === 'Gmail' && !inputLower.includes('gmail')) return false;
      if (selectedVector === 'URL' && !inputLower.includes('http')) return false;
      if (selectedVector === 'Text' && (inputLower.includes('http') || inputLower.includes('gmail'))) return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        (l.input && l.input.toLowerCase().includes(q)) ||
        (l.risk && l.risk.toLowerCase().includes(q)) ||
        (l.reasons && JSON.stringify(l.reasons).toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <PageTransition>
      {/* Header */}
      <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 shadow-xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/15 text-blue-400 rounded-xl border border-blue-500/30">
            <HistoryIcon className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">Scan Audit History</h1>
            <p className="text-xs text-slate-400 font-mono">SIEM Audit Stream • Historical Security Event Log Audit</p>
          </div>
        </div>

        <button
          onClick={fetchLogs}
          disabled={loading}
          className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold flex items-center gap-2 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Logs
        </button>
      </div>

      {/* Control Bar: Risk Filters, Vector Filters & Search */}
      <div className="bg-[#0b1528] p-4 rounded-2xl border border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
        {/* Risk & Vector Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="w-4 h-4 text-slate-500 mr-1" />
          {['All', 'High Risk', 'Suspicious', 'Safe'].map((r) => (
            <button
              key={r}
              onClick={() => setSelectedRisk(r)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition ${
                selectedRisk === r
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-950/40'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {r}
            </button>
          ))}
          <div className="w-px h-5 bg-slate-800 mx-1" />
          {['All', 'URL', 'Gmail', 'Text'].map((v) => (
            <button
              key={v}
              onClick={() => setSelectedVector(v)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono transition ${
                selectedVector === v
                  ? 'bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 font-semibold'
                  : 'bg-slate-950 text-slate-500 hover:text-slate-300 border border-slate-800'
              }`}
            >
              {v}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search inputs or reasons..."
            className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-700/80 rounded-xl text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Security Event Audit Log Table */}
      <div className="bg-[#0b1528] p-6 rounded-2xl border border-slate-800/80 space-y-4">
        {filteredLogs.length === 0 ? (
          <p className="text-xs text-slate-500 italic p-8 text-center">No matching scan history records found.</p>
        ) : (
          <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
            <table className="w-full text-xs text-left text-slate-300">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-mono tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Target Content Payload</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Score</th>
                  <th className="p-3">ML Probability</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 font-sans">
                {filteredLogs.map((log, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/50 transition">
                    <td className="p-3 font-mono text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                    <td className="p-3 font-mono text-slate-200 max-w-md truncate">{log.input}</td>
                    <td className="p-3"><ThreatBadge risk={log.risk} size="sm" /></td>
                    <td className="p-3 font-mono font-bold">{log.score?.toFixed(1)}/10</td>
                    <td className="p-3 text-blue-400 font-mono font-bold">{(log.ml_prob * 100).toFixed(1)}%</td>
                    <td className="p-3 text-right space-x-2">
                      <button
                        onClick={() => setSelectedThreat(log)}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-semibold transition"
                      >
                        Inspect
                      </button>
                      <button
                        onClick={() => setGeminiTarget(log)}
                        className="px-3 py-1 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-lg text-[11px] font-semibold transition"
                      >
                        Ask AI
                      </button>
                    </td>
                  </tr>
                ))}
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

export default History;
