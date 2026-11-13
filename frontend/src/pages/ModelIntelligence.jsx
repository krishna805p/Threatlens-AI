import React from 'react';
import { Cpu, Activity, BarChart2, Layers, CheckCircle2, Sliders, Shield } from 'lucide-react';

export const ModelIntelligence = () => {
  const metrics = [
    { name: 'URL Detector', accuracy: '97.80%', precision: '97.20%', recall: '98.10%', f1: '97.64%', cv: '97.45%' },
    { name: 'Email Detector', accuracy: '96.50%', precision: '95.80%', recall: '97.10%', f1: '96.44%', cv: '96.12%' },
    { name: 'SMS Detector', accuracy: '95.20%', precision: '94.60%', recall: '95.80%', f1: '95.19%', cv: '94.90%' },
    { name: 'Text Detector', accuracy: '94.10%', precision: '93.50%', recall: '94.80%', f1: '94.14%', cv: '93.85%' },
  ];

  const topFeatures = [
    { feature: 'domain_entropy', importance: '0.245', category: 'URL Heuristic' },
    { feature: 'urgency_keywords', importance: '0.198', category: 'NLP Pattern' },
    { feature: 'url_length', importance: '0.152', category: 'URL Structure' },
    { feature: 'ip_in_url', importance: '0.124', category: 'Network Flag' },
    { feature: 'credential_harvest_terms', importance: '0.110', category: 'NLP Pattern' },
    { feature: 'suspicious_tld', importance: '0.088', category: 'Domain Flag' },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Header HUD */}
      <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 shadow-xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-500/15 text-indigo-400 rounded-xl border border-indigo-500/30">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Machine Learning & Model Intelligence</h2>
            <p className="text-xs text-slate-400 font-mono">Classifier Telemetry • Cross-Validation • Feature Importance Matrix</p>
          </div>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl text-xs font-mono text-indigo-300">
          <Activity className="w-3.5 h-3.5" />
          RANDOM FOREST CLASSIFIER
        </div>
      </div>

      {/* Model Accuracy Performance Table */}
      <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-4">
        <h3 className="font-bold text-base text-white flex items-center gap-2">
          <BarChart2 className="w-4 h-4 text-blue-400" />
          Model Evaluation Metrics Matrix
        </h3>

        <div className="overflow-x-auto border border-slate-800/80 rounded-xl">
          <table className="w-full text-xs text-left text-slate-300">
            <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-mono tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3">Model Vector</th>
                <th className="p-3">Accuracy</th>
                <th className="p-3">Precision</th>
                <th className="p-3">Recall</th>
                <th className="p-3">F1 Score</th>
                <th className="p-3">Cross-Val Mean</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 font-mono">
              {metrics.map((m, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40 transition">
                  <td className="p-3 font-semibold text-white font-sans">{m.name}</td>
                  <td className="p-3 font-bold text-emerald-400">{m.accuracy}</td>
                  <td className="p-3 text-slate-200">{m.precision}</td>
                  <td className="p-3 text-slate-200">{m.recall}</td>
                  <td className="p-3 text-blue-400 font-bold">{m.f1}</td>
                  <td className="p-3 text-indigo-300">{m.cv}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Feature Importance & Architecture Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Feature Importance Ranking */}
        <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <h3 className="font-bold text-base text-white flex items-center gap-2">
            <Sliders className="w-4 h-4 text-purple-400" />
            Top Predictive Feature Weights
          </h3>

          <div className="space-y-3">
            {topFeatures.map((item, idx) => {
              const weightPct = parseFloat(item.importance) * 100 * 3.5;
              return (
                <div key={idx} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-xs space-y-1">
                  <div className="flex justify-between font-mono">
                    <span className="font-semibold text-slate-200">{item.feature}</span>
                    <span className="text-purple-400 font-bold">{item.importance}</span>
                  </div>
                  <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-purple-500 h-full rounded-full"
                      style={{ width: `${Math.min(weightPct, 100)}%` }}
                    />
                  </div>
                  <p className="text-[10px] text-slate-500">{item.category}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Model Pipeline Specs */}
        <div className="bg-[#0b1329] p-6 rounded-2xl border border-slate-800/80 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="font-bold text-base text-white flex items-center gap-2 mb-3">
              <Layers className="w-4 h-4 text-emerald-400" />
              Engine Architecture Specifications
            </h3>

            <div className="space-y-3 text-xs">
              <div className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1">
                <p className="font-semibold text-slate-200 font-mono">Model Type</p>
                <p className="text-slate-400">RandomForestClassifier (scikit-learn ensemble)</p>
              </div>

              <div className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1">
                <p className="font-semibold text-slate-200 font-mono">Vectorizers & Transformers</p>
                <p className="text-slate-400">TfidfVectorizer (unigram + bigram text extraction)</p>
              </div>

              <div className="p-3.5 bg-slate-950/60 rounded-xl border border-slate-800 space-y-1">
                <p className="font-semibold text-slate-200 font-mono">Persistence Artifact</p>
                <p className="text-slate-400 font-mono">models/detector.pkl (pickle payload)</p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-indigo-950/20 border border-indigo-500/20 rounded-xl text-xs text-indigo-300">
            <p className="font-semibold flex items-center gap-1.5 mb-1">
              <Shield className="w-4 h-4 text-indigo-400" />
              Protected Core Module
            </p>
            <p className="text-[11px] text-indigo-300/80">
              The trained model binary (`detector.pkl`) operates in read-only inference mode and is consumed directly by the FastAPI backend endpoints.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ModelIntelligence;
