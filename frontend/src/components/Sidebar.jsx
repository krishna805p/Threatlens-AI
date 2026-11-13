import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Globe, 
  MessageSquareText, 
  Mail, 
  History, 
  Cpu,
  Activity
} from 'lucide-react';

export const Sidebar = () => {
  const navItems = [
    { path: '/', label: 'Command Center', icon: LayoutDashboard },
    { path: '/scan/url', label: 'URL Analyzer', icon: Globe },
    { path: '/scan/text', label: 'Text Intelligence', icon: MessageSquareText },
    { path: '/gmail', label: 'Gmail Security', icon: Mail },
    { path: '/history', label: 'Event History', icon: History },
    { path: '/model', label: 'Model Intelligence', icon: Cpu },
  ];

  return (
    <aside className="w-64 bg-[#0b1328] border-r border-slate-800/80 min-h-screen flex flex-col justify-between p-4 shrink-0 select-none">
      <div>
        {/* Brand & SOC Status */}
        <div className="flex items-center gap-3 px-2 py-4 mb-6 border-b border-slate-800/80">
          <div className="p-2.5 bg-blue-600/20 text-blue-400 rounded-xl border border-blue-500/30 shadow-lg shadow-blue-950/50">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h1 className="font-extrabold text-base text-white tracking-wide leading-none">THREATLENS AI</h1>
              <span className="px-1.5 py-0.5 text-[9px] font-bold bg-blue-500/20 text-blue-300 rounded border border-blue-500/30">SOC</span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-1 leading-tight">AI-Powered Cyber Threat Intelligence Platform</p>
          </div>
        </div>

        {/* Navigation Section */}
        <div className="space-y-1">
          <p className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2">OPERATIONS CENTER</p>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `w-full flex items-center justify-between px-3 py-2.5 rounded-xl font-medium text-xs transition-all duration-200 ${
                    isActive
                      ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-lg shadow-blue-950/40 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <div className="flex items-center gap-3">
                      <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                      <span>{item.label}</span>
                    </div>
                    {isActive && <div className="w-1.5 h-1.5 rounded-full bg-blue-400 shadow-sm shadow-blue-400" />}
                  </>
                )}
              </NavLink>
            );
          })}
        </div>
      </div>

      {/* SOC Live System Monitor Footer */}
      <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 space-y-2">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400 font-medium flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            SOC Telemetry
          </span>
          <span className="text-emerald-400 font-bold font-mono">NORMAL</span>
        </div>
        <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
          <div className="bg-gradient-to-r from-blue-500 to-emerald-400 h-full w-4/5 rounded-full" />
        </div>
        <p className="text-[10px] text-slate-500 font-mono text-right">Hybrid Engine v2.4</p>
      </div>
    </aside>
  );
};

export default Sidebar;
