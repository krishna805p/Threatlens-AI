import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/layout/Sidebar';
import Navbar from './components/layout/Navbar';
import Dashboard from './pages/Dashboard';
import UrlScanner from './pages/UrlScanner';
import TextScanner from './pages/TextScanner';
import GmailSecurity from './pages/GmailSecurity';
import History from './pages/History';
import ThreatIntelligence from './pages/ThreatIntelligence';
import AIAssistant from './pages/AIAssistant';
import ModelIntelligence from './pages/ModelIntelligence';
import { ScanProvider } from './context/ScanContext';
import AppLoader from './components/ui/AppLoader';

export function App() {
  return (
    <ScanProvider>
      <AppLoader />
      <Router>
        <div className="flex min-h-screen bg-[#070d19] text-slate-100 font-sans selection:bg-blue-500 selection:text-white">
          {/* Persistent Left Sidebar */}
          <Sidebar />

          {/* Dynamic Route Content Area */}
          <div className="flex-1 flex flex-col min-w-0">
            {/* Top Navbar Header */}
            <Navbar />

            {/* Router Content Container */}
            <main className="flex-1 p-6 overflow-y-auto">
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/scanner/url" element={<UrlScanner />} />
                <Route path="/scan/url" element={<UrlScanner />} />
                <Route path="/scanner/text" element={<TextScanner />} />
                <Route path="/scan/text" element={<TextScanner />} />
                <Route path="/gmail" element={<GmailSecurity />} />
                <Route path="/gmail-security" element={<GmailSecurity />} />
                <Route path="/history" element={<History />} />
                <Route path="/threats" element={<ThreatIntelligence />} />
                <Route path="/assistant" element={<AIAssistant />} />
                <Route path="/model" element={<ModelIntelligence />} />
              </Routes>
            </main>
          </div>
        </div>
      </Router>
    </ScanProvider>
  );
}

export default App;
