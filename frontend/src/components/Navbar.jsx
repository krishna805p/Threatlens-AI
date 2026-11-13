import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import apiService from '../api/client';
import { CheckCircle2, XCircle, Activity, Shield } from 'lucide-react';

export const Navbar = () => {
  const location = useLocation();
  const [status, setStatus] = useState('checking');

  const pageMeta = {
    '/': { title: 'Command Center', subtitle: 'Global SOC Operations & Threat Overview' },
    '/scan/url': { title: 'URL Threat Analyzer', subtitle: 'Phishing Detection & Domain Reputation Engine' },
    '/scan/text': { title: 'Message & Text Intelligence', subtitle: 'NLP Scam Pattern & Urgency Heuristics' },
    '/gmail': { title: 'Gmail Security', subtitle: 'Read-Only Inbox Protection & Batch Scanner' },
    '/history': { title: 'Security Event History', subtitle: 'SIEM Log Audit Stream & Incident Traces' },
    '/model': { title: 'Model Intelligence', subtitle: 'Machine Learning Performance & Telemetry' },
  };

  const meta = pageMeta[location.pathname] || { title: 'Cybersecurity SOC', subtitle: 'Threat Intelligence Platform' };

  useEffect(() => {
    const check = async () => {
      try {
        await apiService.checkHealth();
        setStatus('online');
      } catch (e) {
        setStatus('offline');
      }
    };
    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="bg-[#0b1328]/90 backdrop-blur-md border-b border-slate-800/80 px-6 py-4 flex items-center justify-between sticky top-0 z-20">
      <div>
        <h2 className="text-lg font-extrabold text-white tracking-tight">{meta.title}</h2>
        <p className="text-xs text-slate-400 font-medium">{meta.subtitle}</p>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-950/80 border border-slate-800/80 text-xs">
          {status === 'online' ? (
            <>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-semibold font-mono">BACKEND ONLINE</span>
            </>
          ) : status === 'offline' ? (
            <>
              <XCircle className="w-3.5 h-3.5 text-red-400" />
              <span className="text-red-400 font-semibold font-mono">BACKEND DISCONNECTED</span>
            </>
          ) : (
            <>
              <Activity className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
              <span className="text-amber-400 font-semibold font-mono">CONNECTING...</span>
            </>
          )}
        </div>

        <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-400 border-l border-slate-800 pl-4">
          <Shield className="w-3.5 h-3.5 text-blue-400" />
          <span>PORT 8000</span>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
