import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import apiService from '../../api/client';
import { CheckCircle2, XCircle, Activity, Bell, UserCheck } from 'lucide-react';

export const Navbar = () => {
  const location = useLocation();
  const [status, setStatus] = useState('checking');

  const pageMeta = {
    '/': { title: 'Command Center', breadcrumb: 'SOC / Dashboard / Overview' },
    '/dashboard': { title: 'Command Center', breadcrumb: 'SOC / Dashboard / Overview' },
    '/scanner/url': { title: 'URL Threat Scanner', breadcrumb: 'SOC / Scanners / URL Intelligence' },
    '/scan/url': { title: 'URL Threat Scanner', breadcrumb: 'SOC / Scanners / URL Intelligence' },
    '/scanner/text': { title: 'Message Threat Analyzer', breadcrumb: 'SOC / Scanners / Text NLP Intelligence' },
    '/scan/text': { title: 'Message Threat Analyzer', breadcrumb: 'SOC / Scanners / Text NLP Intelligence' },
    '/gmail': { title: 'Gmail Security Center', breadcrumb: 'SOC / Integrations / Gmail Protection' },
    '/gmail-security': { title: 'Gmail Security Center', breadcrumb: 'SOC / Integrations / Gmail Protection' },
    '/history': { title: 'Scan Audit History', breadcrumb: 'SOC / SIEM / Incident Audit Logs' },
    '/threats': { title: 'Threat Intelligence', breadcrumb: 'SOC / Analytics / Threat Landscape' },
    '/assistant': { title: 'AI Security Analyst', breadcrumb: 'SOC / AI Assistant / Gemini 2.5' },
    '/model': { title: 'Model Intelligence', breadcrumb: 'SOC / ML / Classifier Telemetry' },
  };

  const currentMeta = pageMeta[location.pathname] || { title: 'Cybersecurity SOC', breadcrumb: 'SOC / Operations' };

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
    <header className="bg-[#070d19]/90 backdrop-blur-md border-b border-slate-800/80 px-6 py-4 flex items-center justify-between sticky top-0 z-20">
      <div>
        <p className="text-[11px] font-mono text-slate-500 tracking-wider uppercase mb-0.5">{currentMeta.breadcrumb}</p>
        <h2 className="text-xl font-extrabold text-white tracking-tight">{currentMeta.title}</h2>
      </div>

      <div className="flex items-center gap-4">
        {/* Connection Status Pill */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#0b1528] border border-slate-800 text-xs font-mono">
          {status === 'online' ? (
            <>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-semibold">API ONLINE</span>
            </>
          ) : status === 'offline' ? (
            <>
              <XCircle className="w-3.5 h-3.5 text-red-400" />
              <span className="text-red-400 font-semibold">API DISCONNECTED</span>
            </>
          ) : (
            <>
              <Activity className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
              <span className="text-amber-400 font-semibold">CONNECTING...</span>
            </>
          )}
        </div>

        {/* Security Notification Pulse */}
        <button className="p-2 rounded-xl bg-[#0b1528] border border-slate-800 text-slate-400 hover:text-slate-200 transition relative">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-blue-500 rounded-full animate-ping" />
        </button>

        {/* User Profile Badge */}
        <div className="flex items-center gap-2.5 pl-3 border-l border-slate-800">
          <div className="p-1.5 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-bold text-slate-200 leading-tight">SOC Analyst</p>
            <p className="text-[10px] text-slate-500 font-mono">Security Tier 3</p>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
