import React from 'react';
import { Cpu, Zap, Target, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, CartesianGrid } from 'recharts';

const mockBenchmark = [
  { model: 'Logistic Reg.', accuracy: 98.67, f1: 99.15, sqli_recall: 11.74, latency: 0.3 },
  { model: 'Random Forest', accuracy: 99.34, f1: 99.53, sqli_recall: 83.72, latency: 9.4 },
  { model: 'XGBoost', accuracy: 99.26, f1: 99.48, sqli_recall: 86.07, latency: 5.9 },
  { model: 'LightGBM', accuracy: 99.31, f1: 99.51, sqli_recall: 89.26, latency: 8.0 },
  { model: 'MLP Neural Net', accuracy: 96.70, f1: 97.91, sqli_recall: 84.90, latency: 16.7 },
];

export default function BenchmarkSection({ benchmarkData }) {
  const data = benchmarkData && benchmarkData.length > 0 ? benchmarkData : mockBenchmark;

  return (
    <div className="space-y-8">
      {/* Overview Header */}
      <div className="glass-card p-6 bg-gradient-to-r from-slate-900 via-cyan-950/40 to-slate-900 border-cyan-500/30">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400">
            <Cpu size={24} />
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-white">Machine Learning Model Benchmark Engine</h2>
            <p className="text-xs text-slate-400">Practical 9 & Advanced ML Extension (5 Model Architectures Compared)</p>
          </div>
        </div>
        <p className="text-sm text-slate-300 mt-2">
          Evaluated across 412,287 test samples. <span className="text-cyan-400 font-bold">LightGBM</span> achieved the top SQL Injection attack recall of <span className="text-emerald-400 font-bold">89.26%</span> (+5.54% improvement over Random Forest), while <span className="text-cyan-400 font-bold">Random Forest</span> leads overall accuracy at <span className="text-emerald-400 font-bold">99.34%</span>.
        </p>
      </div>

      {/* Model Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
        {data.map((m, idx) => (
          <div
            key={idx}
            className={`glass-card p-4 flex flex-col justify-between ${
              m.model.includes('LightGBM') || m.model.includes('Random Forest')
                ? 'border-cyan-500/40 bg-cyan-950/20'
                : 'border-slate-800'
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">{m.model}</span>
                {m.model.includes('LightGBM') && (
                  <span className="badge badge-critical text-[10px]">Best Recall</span>
                )}
                {m.model.includes('Random Forest') && (
                  <span className="badge badge-low text-[10px]">Best F1</span>
                )}
              </div>
              <h3 className="text-2xl font-extrabold text-white">{m.accuracy}%</h3>
              <p className="text-xs text-slate-400">Accuracy Score</p>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Weighted F1:</span>
                <span className="font-bold text-emerald-400">{m.f1}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">SQLi Recall:</span>
                <span className="font-bold text-amber-400">{m.sqli_recall}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Latency / 10k:</span>
                <span className="font-mono text-cyan-400">{m.latency} ms</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Metric Comparison Chart */}
      <div className="glass-card p-6">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <Target size={20} className="text-cyan-400" />
          SQL Injection Recall & Overall F1-Score Comparison
        </h3>
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
              <XAxis dataKey="model" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} domain={[0, 100]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  borderRadius: '12px',
                  color: '#fff',
                  fontSize: '12px',
                }}
              />
              <Legend wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
              <Bar dataKey="f1" name="Weighted F1-Score (%)" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              <Bar dataKey="sqli_recall" name="SQLi Recall (%)" fill="#f59e0b" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
