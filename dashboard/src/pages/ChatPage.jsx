import React, { useState, useRef, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  PieChart as RechartsPieChart,
  Pie,
  Cell,
  BarChart as RechartsBarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  Send,
  Bot,
  User,
  ShieldAlert,
  Sparkles,
  FileText,
  Plus,
  Paperclip,
  Cpu,
  Trash2,
  MessageSquare,
  BarChart2,
  PieChart as PieIcon,
} from 'lucide-react';

const defaultWelcomeMessage = {
  sender: 'ai',
  text: `### 👋 Welcome to CyberSentinel AI Log Inspector!

I am your **AI Security Assistant** for **Python for Data Science (Practicals 1 to 10)**.

📁 **Please upload a web access log file (\`.log\` or \`.csv\`) to begin.**
I will answer only from your uploaded file — no file, no analysis.`,
};

export default function ChatPage() {
  // Always start with a fresh new security session when dashboard is opened or reloaded
  const [sessions, setSessions] = useState(() => [
    {
      id: 'session-1',
      title: 'New Security Session',
      activeFilename: null,
      messages: [defaultWelcomeMessage],
    },
  ]);

  const [activeSessionId, setActiveSessionId] = useState('session-1');
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const chatEndRef = useRef(null);

  const activeSession = sessions.find((s) => s.id === activeSessionId) || sessions[0];
  const messages = activeSession ? activeSession.messages : [defaultWelcomeMessage];
  const activeFilename = activeSession ? activeSession.activeFilename : null;

  // Clear any past localStorage cache so reopening dashboard is completely clean
  useEffect(() => {
    try {
      localStorage.clear();
    } catch (e) {}
  }, []);

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const updateActiveSessionMessages = (newMessages, newFilename = null) => {
    setSessions((prevSessions) =>
      prevSessions.map((s) => {
        if (s.id === activeSessionId) {
          const fname = newFilename || s.activeFilename;
          return {
            ...s,
            title: fname || s.title || 'New Security Session',
            activeFilename: fname,
            messages: newMessages,
          };
        }
        return s;
      })
    );
  };

  const handleSendMessage = async (customText = null) => {
    const textToSend = customText || inputMessage;
    if (!textToSend.trim() && !selectedFile) return;

    // Gate: require an uploaded log file before any Q&A
    if (!selectedFile && !activeFilename) {
      const warn = [
        ...messages,
        { sender: 'user', text: textToSend },
        {
          sender: 'ai',
          text: `### 📁 No log file uploaded yet\n\nPlease **upload a \`.log\` or \`.csv\` file first** (paperclip icon below), then ask your question — I only answer from your uploaded file.`,
        },
      ];
      updateActiveSessionMessages(warn);
      if (!customText) setInputMessage('');
      return;
    }

    const currentFileToUse = selectedFile ? selectedFile.name : activeFilename;
    const fileWasUploaded = !!selectedFile;

    const userMsgText = fileWasUploaded
      ? `📄 **Uploaded Log File**: \`${currentFileToUse}\`\n\n${
          textToSend.trim() ? textToSend : '*Execute Practicals 1 to 10 analysis report*'
        }`
      : textToSend;

    const userMsg = {
      sender: 'user',
      text: userMsgText,
      uploadedFilename: fileWasUploaded ? currentFileToUse : null,
    };

    const updatedMessagesWithUser = [...messages, userMsg];
    updateActiveSessionMessages(updatedMessagesWithUser, fileWasUploaded ? currentFileToUse : null);

    if (!customText) setInputMessage('');
    setLoading(true);

    try {
      if (selectedFile) {
        const fileToUpload = selectedFile;
        setSelectedFile(null);

        const formData = new FormData();
        formData.append('file', fileToUpload);

        const res = await fetch('http://localhost:8000/api/chat/upload', {
          method: 'POST',
          body: formData,
        });

        const data = await res.json();
        const finalMessages = [
          ...updatedMessagesWithUser,
          {
            sender: 'ai',
            text: data.response,
            showRetrainOptions: true,
            filename: fileToUpload.name,
            chartData: data.chart_data,
          },
        ];
        updateActiveSessionMessages(finalMessages, fileToUpload.name);
      } else {
        const res = await fetch('http://localhost:8000/api/chat/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: textToSend, filename: activeFilename || null }),
        });

        const data = await res.json();
        const finalMessages = [
          ...updatedMessagesWithUser,
          { sender: 'ai', text: data.response, chartData: data.chart_data },
        ];
        updateActiveSessionMessages(finalMessages);
      }
    } catch (err) {
      console.error(err);
      const fname = currentFileToUse || null;
      if (!fname) {
        updateActiveSessionMessages([...updatedMessagesWithUser, {
          sender: 'ai',
          text: `### 📁 No log file uploaded yet\n\nPlease **upload a \`.log\` or \`.csv\` file first** (paperclip icon below), then ask your question — I only answer from your uploaded file.`,
        }]);
        return;
      }
      const fallbackReport = {
        sender: 'ai',
        text: `### ⚠️ Backend unreachable\n\nCould not reach the analysis backend for \`${fname}\`.\n\n- Make sure the backend is running: \`http://localhost:8000\` (start with \`python3 start_all.py\` or \`uvicorn app:app\` from \`backend/\`).\n- Then re-send your message or re-upload the file to get the **real full-file** analysis (no sampling, no canned numbers).`,
        showRetrainOptions: false,
        filename: fname,
        chartData: null,
      };
      updateActiveSessionMessages([...updatedMessagesWithUser, fallbackReport]);
    } finally {
      setLoading(false);
    }
  };

  const handleRetrainPipeline = async (filenameToRetrain, shouldRetrain) => {
    if (!shouldRetrain) {
      const msgs = [
        ...messages,
        { sender: 'user', text: 'No, keep current model dataset.' },
        {
          sender: 'ai',
          text: `ℹ️ **Understood.** Maintained existing training weights. Machine learning inference will continue using original baseline model.`,
        },
      ];
      updateActiveSessionMessages(msgs);
      return;
    }

    const msgsWithUser = [
      ...messages,
      { sender: 'user', text: `Yes! Retrain Machine Learning Pipeline with ${filenameToRetrain}` },
    ];
    updateActiveSessionMessages(msgsWithUser);
    setLoading(true);

    try {
      const res = await fetch('http://localhost:8000/api/chat/retrain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: filenameToRetrain }),
      });

      const data = await res.json();
      updateActiveSessionMessages([...msgsWithUser, { sender: 'ai', text: data.response, chartData: data.chart_data }]);
    } catch (err) {
      updateActiveSessionMessages([
        ...msgsWithUser,
        {
          sender: 'ai',
          text: `### ⚠️ Retraining failed: backend unreachable\n\nCould not retrain on \`${filenameToRetrain}\` — the backend at \`http://localhost:8000\` is not reachable. No model was updated. Start the backend and try again.`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const processAndUploadFile = async (file) => {
    if (!file) return;

    const userMsg = {
      sender: 'user',
      text: `📄 **Uploaded Log File**: \`${file.name}\`\n\n*Running Practicals 1 to 10 security log analysis...*`,
      uploadedFilename: file.name,
    };

    const updatedMessages = [...messages, userMsg];
    updateActiveSessionMessages(updatedMessages, file.name);
    setSelectedFile(null);
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch('http://localhost:8000/api/chat/upload', {
        method: 'POST',
        body: formData,
      });

      const data = await res.json();
      const finalMessages = [
        ...updatedMessages,
        {
          sender: 'ai',
          text: data.response,
          showRetrainOptions: true,
          filename: file.name,
          chartData: data.chart_data,
        },
      ];
      updateActiveSessionMessages(finalMessages, file.name);
    } catch (err) {
      console.error(err);
      const fallbackReport = {
        sender: 'ai',
        text: `### ⚠️ Upload failed: backend unreachable\n\nCould not upload \`${file.name}\` — the backend at \`http://localhost:8000\` is not reachable.\n\n- Start it with \`python3 start_all.py\`, then upload again.\n- Your file was **not** analyzed; these are not real results, so no canned numbers are shown.`,
        showRetrainOptions: false,
        filename: file.name,
        chartData: null,
      };
      updateActiveSessionMessages([...updatedMessages, fallbackReport], file.name);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      processAndUploadFile(file);
    }
    e.target.value = '';
  };

  const handleNewChat = () => {
    const newId = `session-${Date.now()}`;
    const newSession = {
      id: newId,
      title: 'New Security Session',
      activeFilename: null,
      messages: [defaultWelcomeMessage],
    };
    setSessions((prev) => [newSession, ...prev]);
    setActiveSessionId(newId);
  };

  const handleDeleteSession = (sessionId, e) => {
    e.stopPropagation();
    if (sessions.length <= 1) return;
    const remaining = sessions.filter((s) => s.id !== sessionId);
    setSessions(remaining);
    if (activeSessionId === sessionId) {
      setActiveSessionId(remaining[0].id);
    }
  };

  return (
    <div className="flex h-full bg-[#090d16] text-slate-100 font-sans overflow-hidden">
      {/* Left Sidebar */}
      <aside className="w-80 border-r border-slate-800/80 bg-slate-950/80 flex flex-col justify-between p-4 hidden md:flex">
        <div className="space-y-5 flex-1 flex flex-col min-h-0">
          {/* Brand */}
          <div className="flex items-center gap-3 px-2 flex-shrink-0">
            <div className="w-10 h-10 rounded-xl overflow-hidden shadow-lg border border-cyan-500/40 glow-cyan flex-shrink-0 bg-slate-900">
              <img src="/logo.png" alt="CyberSentinel AI Logo" className="w-full h-full object-cover" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-tight bg-gradient-to-r from-white via-cyan-200 to-blue-400 bg-clip-text text-transparent">
                CyberSentinel AI
              </h1>
              <p className="text-xs text-slate-400 font-medium">Log Inspector • Practicals 1–10</p>
            </div>
          </div>

          {/* New Chat Button */}
          <button
            onClick={handleNewChat}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl border border-slate-700 bg-slate-900 hover:bg-slate-800 transition-all text-sm font-semibold text-white shadow-sm flex-shrink-0"
          >
            <Plus size={18} className="text-cyan-400" /> New Chat Session
          </button>

          {/* Saved Sessions by Log Filename */}
          <div className="flex-1 flex flex-col min-h-0 pt-2 space-y-2">
            <h3 className="text-[11px] font-bold tracking-wider text-slate-400 uppercase px-2 flex items-center justify-between">
              <span>Saved Log Sessions</span>
              <span className="bg-slate-800 text-slate-300 text-[10px] px-1.5 py-0.5 rounded-full">{sessions.length}</span>
            </h3>
            <div className="flex-1 overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
              {sessions.map((s) => {
                const isActive = s.id === activeSessionId;
                return (
                  <div
                    key={s.id}
                    onClick={() => setActiveSessionId(s.id)}
                    className={`group flex items-center justify-between p-2.5 rounded-xl border transition-all cursor-pointer text-xs ${
                      isActive
                        ? 'bg-slate-900 border-cyan-500/60 text-white font-semibold shadow-md'
                        : 'bg-slate-950/60 border-slate-800/80 text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <FileText size={15} className={isActive ? 'text-cyan-400' : 'text-slate-500'} />
                      <span className="truncate font-mono">{s.title || 'New Security Session'}</span>
                    </div>
                    {sessions.length > 1 && (
                      <button
                        onClick={(e) => handleDeleteSession(s.id, e)}
                        className="opacity-0 group-hover:opacity-100 p-1 hover:text-rose-400 transition-opacity"
                        title="Delete Session"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-slate-800/80 text-[11px] text-slate-500 text-center flex-shrink-0">
          BE Computer Engineering • PDS Lab
        </div>
      </aside>

      {/* Main Chat Interface */}
      <main className="flex-1 flex flex-col h-full bg-[#090d16] relative">
        {/* Top Header */}
        <header className="p-4 border-b border-slate-800/80 bg-slate-950/60 backdrop-blur-md flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg overflow-hidden border border-cyan-500/40 shadow-sm flex-shrink-0 bg-slate-900">
              <img src="/logo.png" alt="CyberSentinel AI Logo" className="w-full h-full object-cover" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white tracking-wide">CyberSentinel AI Log Inspector</span>
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse ml-1" title="System Online" />
            </div>
            <span className="text-xs font-mono font-semibold text-amber-400">
              {selectedFile ? (
                `📄 ${selectedFile.name} attached`
              ) : activeFilename ? (
                `📄 ${activeFilename} active`
              ) : (
                `📁 No log file uploaded`
              )}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {activeFilename && (
              <button
                onClick={() => handleRetrainPipeline(activeFilename, true)}
                disabled={loading}
                title={`Retrain Practical 10 model on ${activeFilename}`}
                className="hidden sm:flex items-center gap-1.5 py-1.5 px-3 rounded-lg bg-cyan-600/15 hover:bg-cyan-600/30 text-cyan-300 text-xs font-semibold border border-cyan-500/40 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                <Cpu size={13} /> Retrain Model
              </button>
            )}
            <button
              onClick={handleNewChat}
              className="md:hidden p-2 rounded-lg bg-slate-900 text-slate-300 border border-slate-800"
            >
              <Plus size={16} />
            </button>
          </div>
        </header>

        {/* Chat Messages Feed */}
        <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`flex gap-4 max-w-4xl ${
                msg.sender === 'user' ? 'ml-auto flex-row-reverse' : ''
              }`}
            >
              {/* Avatar */}
              <div
                className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 shadow-md ${
                  msg.sender === 'user'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gradient-to-tr from-cyan-500 to-blue-600 text-white glow-cyan'
                }`}
              >
                {msg.sender === 'user' ? <User size={18} /> : <Bot size={18} />}
              </div>

              {/* Message Content Bubble */}
              <div className="space-y-3 flex-1 min-w-0">
                <div
                  className={`p-4 rounded-2xl border text-sm leading-relaxed ${
                    msg.sender === 'user'
                      ? 'bg-blue-600/90 text-white border-blue-500/50 rounded-tr-none shadow-lg'
                      : 'bg-slate-900/90 text-slate-200 border-slate-800/80 rounded-tl-none shadow-md'
                  }`}
                >
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm]}
                    components={{
                      table: ({ node, ...props }) => (
                        <div className="overflow-x-auto my-3 rounded-lg border border-slate-700/80 shadow-sm">
                          <table className="w-full text-left border-collapse text-xs" {...props} />
                        </div>
                      ),
                      thead: ({ node, ...props }) => (
                        <thead className="bg-slate-800/90 text-slate-200 font-bold border-b border-slate-700" {...props} />
                      ),
                      th: ({ node, ...props }) => <th className="p-2.5 border-r border-slate-700/60 last:border-0" {...props} />,
                      td: ({ node, ...props }) => <td className="p-2.5 border-t border-slate-800 border-r border-slate-800/60 last:border-0" {...props} />,
                      code: ({ node, className, children, ...props }) => {
                        const isInline = !className && !String(children).includes('\n');
                        if (isInline) {
                          return (
                            <code className="bg-slate-800/90 text-cyan-300 px-1.5 py-0.5 rounded font-mono text-xs border border-slate-700/50 inline">
                              {children}
                            </code>
                          );
                        }
                        return (
                          <code className="block bg-slate-950 p-3 rounded-lg text-xs font-mono text-cyan-200 overflow-x-auto border border-slate-800 my-2" {...props}>
                            {children}
                          </code>
                        );
                      },
                    }}
                  >
                    {msg.text}
                  </ReactMarkdown>

                  {/* Render Interactive Charts if available */}
                  {msg.chartData && (
                    <div className="mt-4 p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-4">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <h4 className="text-xs font-bold text-cyan-400 flex items-center gap-1.5 uppercase tracking-wider">
                          <BarChart2 size={15} /> Practical 8 Visual EDA Charts
                        </h4>
                        <span className="text-[10px] text-slate-500 font-mono">Interactive Charts</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* 1. Attack Breakdown Pie Chart */}
                        {msg.chartData.pie_chart && msg.chartData.pie_chart.length > 0 && (
                          <div className="bg-slate-900/90 p-3 rounded-xl border border-slate-800/90 flex flex-col items-center">
                            <p className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1">
                              <PieIcon size={14} className="text-cyan-400" /> Threat Breakdown (Pie Chart)
                            </p>
                            <div className="w-full h-44">
                              <ResponsiveContainer width="100%" height="100%">
                                <RechartsPieChart>
                                  <Pie
                                    data={msg.chartData.pie_chart}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={30}
                                    outerRadius={55}
                                    paddingAngle={3}
                                    dataKey="value"
                                  >
                                    {msg.chartData.pie_chart.map((entry, idx) => (
                                      <Cell key={`cell-${idx}`} fill={entry.color} />
                                    ))}
                                  </Pie>
                                  <RechartsTooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                                  />
                                  <Legend wrapperStyle={{ fontSize: '10px', paddingTop: '4px' }} />
                                </RechartsPieChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}

                        {/* 2. Top Attacking Source IPs Bar Chart */}
                        {msg.chartData.bar_chart && msg.chartData.bar_chart.length > 0 && (
                          <div className="bg-slate-900/90 p-3 rounded-xl border border-slate-800/90 flex flex-col items-center">
                            <p className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1">
                              <BarChart2 size={14} className="text-cyan-400" /> Top Attacking IPs (Bar Chart)
                            </p>
                            <div className="w-full h-44">
                              <ResponsiveContainer width="100%" height="100%">
                                <RechartsBarChart data={msg.chartData.bar_chart} margin={{ top: 10, right: 10, left: -25, bottom: 25 }}>
                                  <XAxis dataKey="ip" tick={{ fill: '#94a3b8', fontSize: 8 }} angle={-25} textAnchor="end" />
                                  <YAxis tick={{ fill: '#94a3b8', fontSize: 8 }} />
                                  <RechartsTooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                                  />
                                  <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                                </RechartsBarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}

                        {/* 3. Attacking Tool Breakdown Bar Chart (which bot?) */}
                        {msg.chartData.bot_chart && msg.chartData.bot_chart.length > 0 && (
                          <div className="bg-slate-900/90 p-3 rounded-xl border border-slate-800/90 flex flex-col items-center md:col-span-2">
                            <p className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1">
                              <Bot size={14} className="text-cyan-400" /> Attacking Tools — Which Bot? (Bar Chart)
                            </p>
                            <div className="w-full h-48">
                              <ResponsiveContainer width="100%" height="100%">
                                <RechartsBarChart data={msg.chartData.bot_chart} margin={{ top: 10, right: 10, left: -25, bottom: 25 }}>
                                  <XAxis dataKey="tool" tick={{ fill: '#94a3b8', fontSize: 8 }} angle={-25} textAnchor="end" interval={0} />
                                  <YAxis tick={{ fill: '#94a3b8', fontSize: 8 }} />
                                  <RechartsTooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                                  />
                                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                                    {msg.chartData.bot_chart.map((entry, idx) => (
                                      <Cell key={`botcell-${idx}`} fill={entry.color || '#38bdf8'} />
                                    ))}
                                  </Bar>
                                </RechartsBarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}

                        {/* 4. SQLi Payload Variants Bar Chart (which injection technique?) */}
                        {msg.chartData.sqli_chart && msg.chartData.sqli_chart.length > 0 && (
                          <div className="bg-slate-900/90 p-3 rounded-xl border border-slate-800/90 flex flex-col items-center md:col-span-2">
                            <p className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1">
                              <Bot size={14} className="text-red-400" /> SQLi Variants — Which Technique? (Bar Chart)
                            </p>
                            <div className="w-full h-48">
                              <ResponsiveContainer width="100%" height="100%">
                                <RechartsBarChart data={msg.chartData.sqli_chart} margin={{ top: 10, right: 10, left: -25, bottom: 25 }}>
                                  <XAxis dataKey="variant" tick={{ fill: '#94a3b8', fontSize: 8 }} angle={-25} textAnchor="end" interval={0} />
                                  <YAxis tick={{ fill: '#94a3b8', fontSize: 8 }} />
                                  <RechartsTooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                                  />
                                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                                    {msg.chartData.sqli_chart.map((entry, idx) => (
                                      <Cell key={`sqlicell-${idx}`} fill={entry.color || '#f97316'} />
                                    ))}
                                  </Bar>
                                </RechartsBarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex gap-4 max-w-4xl">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white flex items-center justify-center glow-cyan">
                <Bot size={18} className="animate-spin" />
              </div>
              <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 text-xs text-slate-400 flex items-center gap-2 shadow-md">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                Executing Practicals 1 to 10 pipeline & analyzing log security...
              </div>
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="max-w-4xl mx-auto space-y-2"
          >
            {/* File Attachment Box */}
            {selectedFile && (
              <div className="flex items-center justify-between p-2 px-3 rounded-xl bg-amber-950/40 border border-amber-500/50 text-amber-300 text-xs shadow-sm">
                <div className="flex items-center gap-2 truncate">
                  <FileText size={15} className="text-amber-400 flex-shrink-0" />
                  <span className="font-semibold truncate">📄 {selectedFile.name}</span>
                  <span className="text-[10px] bg-amber-500/20 px-2 py-0.5 rounded text-amber-200">Ready to analyze</span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedFile(null)}
                  className="p-1 hover:text-white transition-colors"
                >
                  ✕
                </button>
              </div>
            )}

            {/* File must be uploaded before Q&A — no canned questions shown */}

            <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-2xl p-2 focus-within:border-cyan-500/60 transition-all shadow-inner">
              <label className="p-2 text-slate-400 hover:text-cyan-400 cursor-pointer transition-colors">
                <Paperclip size={18} />
                <input
                  type="file"
                  accept=".log,.txt,.csv"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
              <input
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                placeholder="Upload a log file first, then ask about it..."
                className="flex-1 bg-transparent border-none text-slate-100 placeholder-slate-500 text-sm focus:outline-none px-2"
              />
              <button
                type="submit"
                disabled={loading || (!inputMessage.trim() && !selectedFile)}
                className="p-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold shadow-lg hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                <Send size={16} />
              </button>
            </div>
          </form>
        </div>
      </main>
    </div>
  );
}
