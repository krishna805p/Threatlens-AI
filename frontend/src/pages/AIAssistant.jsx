import React from 'react';
import { PageTransition } from '../components/layout/PageTransition';
import { AIChat } from '../components/ai/AIChat';
import { Sparkles, Shield, Cpu, Zap, MessageSquare, Terminal } from 'lucide-react';

import ElectricBorder from '../components/ui/ElectricBorder';

export const AIAssistant = () => {
  return (
    <PageTransition className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <ElectricBorder color="#6366f1" glowColor="#a5b4fc">
        <div className="p-6 flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 text-indigo-400 rounded-xl border border-indigo-500/30">
              <Sparkles className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                AI Analyst Workspace
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/30">
                  GEMINI 2.5 INTEGRATED
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Conversational Threat Intelligence • Explanation Engine • Incident Mitigation Guidance
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
            <div className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-xl flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span>Endpoint: POST /explain</span>
            </div>
            <div className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-xl flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
              <span>Active Pipeline</span>
            </div>
          </div>
        </div>
      </ElectricBorder>

      {/* Main Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Chat Component (3 Columns) */}
        <div className="lg:col-span-3">
          <AIChat />
        </div>

        {/* System Capabilities Sidebar (1 Column) */}
        <div className="space-y-4">
          <div className="bg-[#0b1329] p-5 rounded-2xl border border-slate-800/80 space-y-4">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Shield className="w-4 h-4 text-indigo-400" />
              Assistant Capabilities
            </h3>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1">
                <p className="font-semibold text-slate-200 flex items-center gap-1.5 font-mono">
                  <Terminal className="w-3.5 h-3.5 text-blue-400" /> Explainability
                </p>
                <p className="text-[11px] text-slate-400">
                  Translates complex ML feature weights and heuristic rules into human-readable attack descriptions.
                </p>
              </div>

              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1">
                <p className="font-semibold text-slate-200 flex items-center gap-1.5 font-mono">
                  <Zap className="w-3.5 h-3.5 text-amber-400" /> Remediation Guidance
                </p>
                <p className="text-[11px] text-slate-400">
                  Provides step-by-step SOC incident response playbooks for flagged threats and false positives.
                </p>
              </div>

              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1">
                <p className="font-semibold text-slate-200 flex items-center gap-1.5 font-mono">
                  <MessageSquare className="w-3.5 h-3.5 text-purple-400" /> Threat Intelligence
                </p>
                <p className="text-[11px] text-slate-400">
                  Clarifies emerging threat vectors including spear phishing, homograph attacks, and credential theft.
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-br from-indigo-950/30 to-purple-950/20 p-5 rounded-2xl border border-indigo-500/20 text-xs space-y-2">
            <h4 className="font-bold text-indigo-300 flex items-center gap-1.5 font-mono">
              <Sparkles className="w-3.5 h-3.5 text-indigo-400" /> SOC Best Practice
            </h4>
            <p className="text-[11px] text-indigo-200/80 leading-relaxed">
              When analyzing flagged emails or URLs, navigate directly to the respective scanner page and click "Explain with Gemini" to preload the exact detection context.
            </p>
          </div>
        </div>
      </div>
    </PageTransition>
  );
};

export default AIAssistant;
