import React from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Globe, 
  MessageSquareText, 
  Mail, 
  History, 
  Sparkles, 
  BarChart3,
  Activity,
  Radio
} from 'lucide-react';

import ElectricBorder from '../ui/ElectricBorder';

export const Sidebar = () => {
  const navItems = [
    { path: '/dashboard', label: 'Command Center', icon: LayoutDashboard },
    { path: '/scanner/url', label: 'URL Threat Scanner', icon: Globe },
    { path: '/scanner/text', label: 'Message Intelligence', icon: MessageSquareText },
    { path: '/gmail', label: 'Gmail Security Center', icon: Mail },
    { path: '/history', label: 'Scan Audit History', icon: History },
    { path: '/threats', label: 'Threat Intelligence', icon: BarChart3 },
    { path: '/assistant', label: 'AI Analyst Assistant', icon: Sparkles },
  ];

  return (
    <aside className="w-64 bg-[#070d19] border-r border-slate-800/80 min-h-screen flex flex-col justify-between p-4 shrink-0 select-none z-30">
      <div>
        {/* Brand Header */}
        <div className="flex items-center gap-3 px-2 py-4 mb-6 border-b border-slate-800/80">
          <div className="relative p-2.5 bg-blue-600/15 text-blue-400 rounded-xl border border-blue-500/30 shadow-lg shadow-blue-950/60">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-blue-400 rounded-full animate-ping" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h1 className="font-extrabold text-base text-white tracking-wider leading-none font-mono">THREATLENS AI</h1>
              <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-blue-500/20 text-blue-300 rounded border border-blue-500/30">SOC</span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-1 leading-tight">AI-Powered Cyber Threat Intelligence Platform</p>
          </div>
        </div>

        {/* Navigation Section */}
        <div className="space-y-1">
          <p className="px-3 text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 mb-2">SOC NAVIGATION</p>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `w-full flex items-center justify-between px-3.5 py-3 rounded-xl font-medium text-xs transition-all duration-200 ${
                    isActive
                      ? 'bg-gradient-to-r from-blue-600/20 to-indigo-600/10 text-blue-400 border border-blue-500/30 shadow-lg shadow-blue-950/40 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <div className="flex items-center gap-3">
                      <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                      <span>{item.label}</span>
                    </div>
                    {isActive && (
                      <motion.div
                        layoutId="activeIndicator"
                        className="w-1.5 h-1.5 rounded-full bg-blue-400 shadow-sm shadow-blue-400"
                        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                      />
                    )}
                  </>
                )}
              </NavLink>
            );
          })}
        </div>
      </div>

      {/* Live System Telemetry HUD */}
      <ElectricBorder color="#10b981" glowColor="#34d399">
        <div className="p-3.5 space-y-2.5">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-mono flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              SYSTEM HUD
            </span>
            <span className="text-emerald-400 font-mono font-bold text-[10px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              ONLINE
            </span>
          </div>
          <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-slate-800/50">
            <motion.div 
              initial={{ width: '0%' }}
              animate={{ width: '85%' }}
              transition={{ duration: 1.2, ease: 'easeOut' }}
              className="bg-gradient-to-r from-blue-500 to-emerald-400 h-full rounded-full" 
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-500 font-mono">
            <span>FastAPI Backend</span>
            <span>127.0.0.1:8000</span>
          </div>
        </div>
      </ElectricBorder>
    </aside>
  );
};

export default Sidebar;
