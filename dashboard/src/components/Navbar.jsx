import React from 'react';
import { ShieldAlert, Activity, Cpu, BookOpen, Terminal, CheckCircle2 } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, apiOnline }) {
  const tabs = [
    { id: 'overview', label: 'Security Dashboard', icon: Activity },
    { id: 'syllabus', label: 'Practicals 1–10 Manual', icon: BookOpen },
    { id: 'benchmark', label: 'ML Benchmark', icon: Cpu },
    { id: 'predict', label: 'Live Threat Tester', icon: ShieldAlert },
  ];

  return (
    <header className="sticky top-0 z-50 glass-card rounded-none border-x-0 border-t-0 px-6 py-4 mb-8">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white shadow-lg glow-cyan">
            <ShieldAlert size={26} />
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              CYBERLOG AI <span className="text-cyan-400 text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800 ml-1">PDS Lab</span>
            </h1>
            <p className="text-xs text-slate-400 font-medium">BE Computer Engineering • Practical 1 to 10 Suite</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-slate-900/80 p-1.5 rounded-xl border border-slate-800">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-200 ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Icon size={16} />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* API Status Badge */}
        <div className="flex items-center gap-2 text-xs px-3 py-1.5 rounded-full bg-slate-900/90 border border-slate-800">
          <span className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
          <span className="text-slate-300 font-medium">{apiOnline ? 'API Online :8000' : 'Offline / Standalone Mode'}</span>
        </div>
      </div>
    </header>
  );
}
