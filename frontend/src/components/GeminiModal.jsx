import React, { useState } from 'react';
import { X, Sparkles, Send, Loader2 } from 'lucide-react';
import apiService from '../api/client';

export const GeminiModal = ({ detection, onClose }) => {
  const [question, setQuestion] = useState('Explain this detection and recommend safe next steps.');
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [explanation, setExplanation] = useState('');

  const handleAsk = async (e) => {
    if (e) e.preventDefault();
    if (!question.trim()) return;

    setLoading(true);
    try {
      const res = await apiService.explainDetection(detection, question, history);
      const answer = res.explanation || 'No explanation available.';
      setExplanation(answer);
      setHistory((prev) => [...prev, { question, answer }]);
    } catch (err) {
      setExplanation('AI Security Assistant is currently unavailable. Check GEMINI_API_KEY environment configuration.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-[#0b1528] border border-indigo-500/30 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl shadow-indigo-950/50 flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-[#0b1528] z-10">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/15 text-indigo-400 rounded-xl border border-indigo-500/30">
              <Sparkles className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-lg text-white">AI Security Assistant</h3>
              <p className="text-xs text-slate-400">Powered by Google Gemini 2.5 Flash</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 flex-1 overflow-y-auto">
          {/* Explanation Answer Box */}
          {explanation ? (
            <div className="p-4 bg-indigo-950/30 border border-indigo-500/20 rounded-xl text-sm text-slate-200 leading-relaxed whitespace-pre-line">
              <p className="text-xs text-indigo-400 font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                AI Security Guidance
              </p>
              {explanation}
            </div>
          ) : (
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-400">
              Ask a question below to receive AI-powered threat analysis and safe action recommendations based on this detection.
            </div>
          )}

          {/* Previous Conversation History */}
          {history.length > 1 && (
            <div className="space-y-3 pt-2">
              <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Previous Exchanges</p>
              {history.slice(0, -1).map((h, i) => (
                <div key={i} className="p-3 bg-slate-900/40 rounded-xl border border-slate-800/80 text-xs space-y-1">
                  <p className="font-semibold text-slate-300">Q: {h.question}</p>
                  <p className="text-slate-400 line-clamp-3">{h.answer}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Question Form */}
        <form onSubmit={handleAsk} className="p-4 border-t border-slate-800 bg-slate-900/60 flex gap-2">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask AI Assistant about this threat..."
            className="flex-1 px-4 py-2.5 bg-slate-950 border border-slate-700/80 rounded-xl text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
          <button
            type="submit"
            disabled={loading || !question.trim()}
            className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-xl font-semibold text-xs flex items-center gap-2 transition"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            Ask AI
          </button>
        </form>
      </div>
    </div>
  );
};

export default GeminiModal;
