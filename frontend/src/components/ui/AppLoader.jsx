import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Cpu, Activity, CheckCircle2 } from 'lucide-react';
import WarpText from './WarpText';

export const AppLoader = ({ onComplete }) => {
  const [progress, setProgress] = useState(15);
  const [statusText, setStatusText] = useState('Initializing ThreatLens AI');
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    // Check session storage to ensure loader only runs once per app session
    const hasLoaded = sessionStorage.getItem('threatlens_app_loaded');
    if (hasLoaded) {
      setIsVisible(false);
      if (onComplete) onComplete();
      return;
    }

    const steps = [
      { p: 35, text: 'Securing your workspace' },
      { p: 65, text: 'Loading ML Classifiers & Rules' },
      { p: 90, text: 'Connecting Threat Intelligence' },
      { p: 100, text: 'System Operational' },
    ];

    let currentStep = 0;

    const interval = setInterval(() => {
      if (currentStep < steps.length) {
        setProgress(steps[currentStep].p);
        setStatusText(steps[currentStep].text);
        currentStep++;
      } else {
        clearInterval(interval);
        setTimeout(() => {
          sessionStorage.setItem('threatlens_app_loaded', 'true');
          setIsVisible(false);
          if (onComplete) onComplete();
        }, 300);
      }
    }, 450);

    // Hard fallback cap to guarantee loader never locks UI longer than 2.5s
    const fallbackTimer = setTimeout(() => {
      clearInterval(interval);
      sessionStorage.setItem('threatlens_app_loaded', 'true');
      setIsVisible(false);
      if (onComplete) onComplete();
    }, 2500);

    return () => {
      clearInterval(interval);
      clearTimeout(fallbackTimer);
    };
  }, [onComplete]);

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 0.98 }}
          transition={{ duration: 0.5, ease: 'easeInOut' }}
          className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#070d19] text-white select-none p-6"
        >
          {/* Subtle Ambient Background Gradients */}
          <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 translate-y-1/2 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

          {/* Central Visual Identity */}
          <div className="relative flex flex-col items-center max-w-md w-full space-y-6 text-center">
            {/* Shield Logo with Radar Pulse */}
            <div className="relative p-5 bg-gradient-to-br from-blue-600/20 to-indigo-600/10 text-blue-400 rounded-3xl border border-blue-500/30 shadow-2xl shadow-blue-950/80">
              <ShieldAlert className="w-12 h-12 animate-pulse" />
              <div className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-blue-400 rounded-full animate-ping" />
            </div>

            {/* Title with WarpText */}
            <div className="space-y-1">
              <WarpText text="THREATLENS AI" className="h-14" fontSize={26} color="#ffffff" />
              <p className="text-xs text-slate-400 font-mono tracking-widest uppercase">
                Cyber Threat Intelligence Platform
              </p>
            </div>

            {/* Progress & Scanning Indicator */}
            <div className="w-full space-y-3 pt-4">
              <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800/80 shadow-inner">
                <motion.div
                  className="h-full bg-gradient-to-r from-blue-500 via-indigo-500 to-emerald-400 rounded-full"
                  initial={{ width: '15%' }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 0.3, ease: 'easeOut' }}
                />
              </div>

              <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
                <span className="flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                  {statusText}
                </span>
                <span className="font-bold text-blue-400">{progress}%</span>
              </div>
            </div>

            {/* Bottom Security Telemetry Tag */}
            <div className="pt-6 flex items-center gap-2 text-[11px] font-mono text-slate-500">
              <Cpu className="w-3.5 h-3.5 text-emerald-400" />
              <span>SOC HYBRID ENGINE v2.4 • FASTAPI + GEMINI 2.5</span>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default AppLoader;
