import React, { useState } from 'react';
import { BookOpen, Bot } from 'lucide-react';
import StorybookPage from './pages/StorybookPage';
import ChatPage from './pages/ChatPage';

export default function App() {
  const [activeTab, setActiveTab] = useState('story');

  return (
    <div className="flex flex-col h-screen bg-[#090d16] text-slate-100 font-sans overflow-hidden">
      {/* Top navigation: two pages */}
      <nav className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl overflow-hidden border border-cyan-500/40 bg-slate-900 shrink-0">
            <img src="/logo.png" alt="CyberSentinel AI Logo" className="w-full h-full object-cover" />
          </div>
          <div className="hidden sm:block">
            <h1 className="text-sm font-extrabold tracking-tight bg-gradient-to-r from-white via-cyan-200 to-blue-400 bg-clip-text text-transparent leading-tight">
              CyberSentinel AI
            </h1>
            <p className="text-[10px] text-slate-500 font-medium">PDS Lab • Practicals 1–10</p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-xl p-1">
          <button
            onClick={() => setActiveTab('story')}
            className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'story'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen size={14} /> Practical Story
          </button>
          <button
            onClick={() => setActiveTab('chat')}
            className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'chat'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bot size={14} /> AI Chat Inspector
          </button>
        </div>
      </nav>

      {/* Page body */}
      <div className="flex-1 min-h-0">
        {activeTab === 'story' ? <StorybookPage /> : <ChatPage />}
      </div>
    </div>
  );
}
