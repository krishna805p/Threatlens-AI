import React, { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Send, Bot, User, Sparkles, RefreshCw, ShieldCheck, Terminal } from 'lucide-react';
import apiService from '../../api/client';

export const AIChat = ({ initialDetection = null }) => {
  const [messages, setMessages] = useState([
    {
      id: 'welcome-1',
      sender: 'ai',
      text: 'Greetings, SOC Analyst. I am ThreatLens AI Security Assistant powered by Gemini. I can explain detection signals, analyze threat indicators, recommend remediation protocols, or answer general security inquiries.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  const suggestedQuestions = [
    'How does domain entropy indicate a phishing URL?',
    'What remediation steps are recommended for high-risk emails?',
    'Explain how rule-engine heuristics combine with ML predictions.',
    'What features increase the risk score of a suspicious SMS?',
  ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSend = async (questionText = null) => {
    const textToSend = questionText || input;
    if (!textToSend.trim() || loading) return;

    const userMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMessage]);
    if (!questionText) setInput('');
    setLoading(true);

    try {
      // Build conversation history for API payload
      const historyPayload = messages
        .filter((m) => m.id !== 'welcome-1')
        .map((m) => ({
          role: m.sender === 'user' ? 'user' : 'assistant',
          content: m.text,
        }));

      const res = await apiService.explainDetection(
        initialDetection || {
          source: 'interactive_chat',
          risk_level: 'NEUTRAL',
          risk_score: 0,
          reasons: ['User SOC Inquiry'],
        },
        textToSend,
        historyPayload
      );

      const aiExplanation = res.explanation || res.message || 'No response payload received from AI model.';

      const aiMessage = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: aiExplanation,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, aiMessage]);
    } catch (err) {
      console.error('AIChat error:', err);
      const errorMessage = {
        id: `error-${Date.now()}`,
        sender: 'ai',
        isError: true,
        text: 'Unable to process query. The Gemini AI Security Assistant backend service may be offline or rate limited.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setMessages([
      {
        id: 'welcome-1',
        sender: 'ai',
        text: 'Chat history cleared. Standby for new threat analysis query.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  };

  return (
    <div className="flex flex-col h-[750px] bg-[#0b1329] rounded-2xl border border-slate-800/80 shadow-2xl overflow-hidden">
      {/* Workspace Header */}
      <div className="px-6 py-4 bg-[#070d19] border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 text-indigo-400 rounded-xl border border-indigo-500/30 shadow-lg shadow-indigo-950/40">
            <Bot className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-white text-sm tracking-wide">SOC AI Security Analyst</h3>
              <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/30">
                GEMINI 2.5
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">Neural Threat Explanation & Remediation Engine</p>
          </div>
        </div>

        <button
          onClick={handleClear}
          className="p-2 rounded-xl bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800 hover:border-slate-700 transition flex items-center gap-1.5 text-xs font-mono"
          title="Clear Conversation"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Reset Session</span>
        </button>
      </div>

      {/* Optional Active Detection Context Header */}
      {initialDetection && (
        <div className="px-6 py-2.5 bg-blue-950/30 border-b border-blue-500/20 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2 text-blue-300">
            <Terminal className="w-4 h-4 text-blue-400" />
            <span>Active Context: <strong className="text-white">{initialDetection.source || 'Scan Payload'}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Risk Score:</span>
            <span className="font-bold text-amber-400">{initialDetection.risk_score || 0}/100</span>
          </div>
        </div>
      )}

      {/* Chat Messages Stream */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4 font-sans">
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          return (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
              className={`flex gap-3 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
            >
              {/* Avatar Icon */}
              <div
                className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 font-mono text-xs font-bold border ${
                  isUser
                    ? 'bg-blue-600/20 text-blue-300 border-blue-500/30'
                    : msg.isError
                    ? 'bg-red-500/20 text-red-400 border-red-500/30'
                    : 'bg-purple-600/20 text-purple-300 border-purple-500/30'
                }`}
              >
                {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div className={`max-w-[80%] space-y-1 ${isUser ? 'items-end' : 'items-start'}`}>
                <div
                  className={`p-4 rounded-2xl text-xs leading-relaxed ${
                    isUser
                      ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-tr-xs shadow-lg shadow-blue-950/30'
                      : msg.isError
                      ? 'bg-red-950/40 border border-red-500/30 text-red-200 rounded-tl-xs'
                      : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-xs shadow-md font-sans whitespace-pre-wrap'
                  }`}
                >
                  {msg.text}
                </div>

                <div
                  className={`flex items-center gap-2 px-1 text-[10px] font-mono text-slate-500 ${
                    isUser ? 'justify-end' : 'justify-start'
                  }`}
                >
                  <span>{msg.timestamp}</span>
                  {!isUser && !msg.isError && (
                    <span className="flex items-center gap-1 text-emerald-400">
                      <ShieldCheck className="w-3 h-3" /> AI VERIFIED
                    </span>
                  )}
                </div>
              </div>
            </motion.div>
          );
        })}

        {/* Loading Indicator */}
        {loading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center gap-3 text-xs text-indigo-400 font-mono"
          >
            <div className="w-8 h-8 rounded-xl bg-purple-600/20 border border-purple-500/30 flex items-center justify-center">
              <Bot className="w-4 h-4 animate-spin text-purple-400" />
            </div>
            <div className="px-4 py-3 bg-slate-900/90 border border-slate-800 rounded-2xl rounded-tl-xs flex items-center gap-2">
              <Sparkles className="w-4 h-4 animate-pulse text-indigo-400" />
              <span>Gemini is generating security explanation...</span>
            </div>
          </motion.div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Prompt Selector Pills */}
      <div className="px-6 py-2.5 bg-[#070d19]/80 border-t border-slate-800/80 overflow-x-auto flex items-center gap-2 scrollbar-none">
        <span className="text-[10px] font-mono text-slate-500 shrink-0 uppercase tracking-wider">Prompts:</span>
        {suggestedQuestions.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(q)}
            disabled={loading}
            className="px-3 py-1 bg-slate-900 hover:bg-indigo-950/50 border border-slate-800 hover:border-indigo-500/40 rounded-full text-[11px] text-slate-300 hover:text-indigo-200 transition shrink-0 font-sans"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input Console */}
      <div className="p-4 bg-[#070d19] border-t border-slate-800/80">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-3"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask AI Assistant to analyze threat telemetry or clarify security recommendations..."
            disabled={loading}
            className="flex-1 px-4 py-3 bg-slate-950 border border-slate-800 focus:border-indigo-500 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 transition font-mono"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="px-5 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 disabled:opacity-50 text-white rounded-xl font-medium text-xs flex items-center gap-2 transition shadow-lg shadow-indigo-950/50 shrink-0 font-mono"
          >
            <span>SEND</span>
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
};

export default AIChat;
