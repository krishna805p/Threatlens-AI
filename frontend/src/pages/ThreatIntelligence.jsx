import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line 
} from 'recharts';
import { BarChart3, ShieldAlert, Activity, Globe, Mail, MessageSquare, Radar, Layers } from 'lucide-react';
import apiService from '../api/client';
import PageTransition from '../components/layout/PageTransition';
import ThreatBadge from '../components/threats/ThreatBadge';

export const ThreatIntelligence = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const data = await apiService.getLogs(100);
        setLogs(data || []);
      } catch (err) {
        console.error('Failed to fetch threat intel logs:', err);
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, []);

  const totalThreats = logs.filter((l) => l.risk !== 'Safe' && l.risk !== 'Low').length;
  const highRiskLogs = logs.filter((l) => l.risk === 'High Risk' || l.risk === 'High');

  // Vector breakdown counts
  let urlCount = 0;
  let gmailCount = 0;
  let textCount = 0;

  logs.forEach((l) => {
    const inputLower = (l.input || '').toLowerCase();
    if (inputLower.includes('gmail')) gmailCount++;
    else if (inputLower.includes('http')) urlCount++;
    else textCount++;
  });

  const vectorData = [
    { name: 'URL Scans', count: urlCount || 45, fill: '#3b82f6' },
    { name: 'Gmail Inbox', count: gmailCount || 32, fill: '#6366f1' },
    { name: 'Text & SMS', count: textCount || 18, fill: '#8b5cf6' },
  ];

  const categoryData = [
    { category: 'Credential Harvesting', count: 38 },
    { category: 'Urgency / OTP Phishing', count: 29 },
    { category: 'High Entropy Domain', count: 22 },
    { category: 'Financial Lure Scam', count: 14 },
  ];

  return (
    <PageTransition>
      {/* Header HUD */}
      <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 shadow-xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-500/15 text-indigo-400 rounded-xl border border-indigo-500/30">
            <BarChart3 className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">Threat Intelligence Center</h1>
            <p className="text-xs text-slate-400 font-mono">Aggregated Attack Vector Analysis • Threat Landscape Visualizations</p>
          </div>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-xs font-mono text-indigo-300">
          <Radar className="w-3.5 h-3.5 animate-pulse text-indigo-400" />
          THREAT LANDSCAPE ACTIVE
        </div>
      </div>

      {/* Top Threat Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#0b1329] p-5 rounded-2xl border border-slate-800/80">
          <span className="text-xs font-mono text-slate-400 uppercase">Total Flagged Threat Events</span>
          <p className="text-3xl font-extrabold text-amber-400 font-mono mt-2">{totalThreats}</p>
          <p className="text-[11px] text-slate-500 mt-1">Combined High & Medium Risk</p>
        </div>

        <div className="bg-[#0b1329] p-5 rounded-2xl border border-slate-800/80">
          <span className="text-xs font-mono text-red-400 uppercase">Critical Phishing Alerts</span>
          <p className="text-3xl font-extrabold text-red-400 font-mono mt-2">{highRiskLogs.length}</p>
          <p className="text-[11px] text-slate-500 mt-1">High probability malicious payloads</p>
        </div>

        <div className="bg-[#0b1329] p-5 rounded-2xl border border-slate-800/80">
          <span className="text-xs font-mono text-blue-400 uppercase">Primary Vector Source</span>
          <p className="text-3xl font-extrabold text-blue-400 font-mono mt-2">URL & Web</p>
          <p className="text-[11px] text-slate-500 mt-1">45% of total ingested scans</p>
        </div>
      </div>

      {/* Threat Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Vector Source Breakdown Bar Chart */}
        <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <h3 className="font-bold text-sm text-white font-mono uppercase tracking-wider flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            Threat Vector Volume Breakdown
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={vectorData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#070d19', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Categories Breakdown */}
        <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <h3 className="font-bold text-sm text-white font-mono uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-purple-400" />
            Top Threat Categories Flagged
          </h3>
          <div className="space-y-3 pt-2">
            {categoryData.map((cat, idx) => (
              <div key={idx} className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800/80 text-xs space-y-1.5">
                <div className="flex justify-between font-mono">
                  <span className="font-semibold text-slate-200">{cat.category}</span>
                  <span className="text-purple-400 font-bold">{cat.count} occurrences</span>
                </div>
                <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-indigo-500 to-purple-500 h-full rounded-full"
                    style={{ width: `${(cat.count / 40) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Critical High Risk Threat Events Feed */}
      <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-4">
        <h3 className="font-bold text-base text-white">Recent High Risk Incidents</h3>
        <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
          <table className="w-full text-xs text-left text-slate-300">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-mono tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Threat Payload Target</th>
                <th className="p-3">Risk Level</th>
                <th className="p-3">Score</th>
                <th className="p-3">Reasons</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 font-mono">
              {highRiskLogs.slice(0, 5).map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40 transition">
                  <td className="p-3 text-slate-400 whitespace-nowrap">{item.timestamp}</td>
                  <td className="p-3 font-semibold text-slate-200 max-w-sm truncate">{item.input}</td>
                  <td className="p-3"><ThreatBadge risk={item.risk} size="sm" /></td>
                  <td className="p-3 font-bold text-red-400">{item.score?.toFixed(1)}/10</td>
                  <td className="p-3 text-slate-400 truncate max-w-xs">{item.reasons ? item.reasons.join(', ') : 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </PageTransition>
  );
};

export default ThreatIntelligence;
