import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts';
import { TrendingUp } from 'lucide-react';

const mockHourlyData = [
  { date: '2024-02-01', benign: 300, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-02', benign: 350, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-03', benign: 280, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-04', benign: 310, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-05', benign: 340, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-06', benign: 327, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-07', benign: 231, brute_force: 9, sqli: 0, path_traversal: 0 },
  { date: '2024-02-08', benign: 320, brute_force: 617896, sqli: 0, path_traversal: 0 },
  { date: '2024-02-09', benign: 364, brute_force: 687638, sqli: 2, path_traversal: 0 },
  { date: '2024-02-10', benign: 322, brute_force: 0, sqli: 0, path_traversal: 0 },
  { date: '2024-02-15', benign: 2749, brute_force: 371, sqli: 92, path_traversal: 16 },
];

export default function TrafficChart({ data }) {
  const chartData = data && data.length > 0 ? data : mockHourlyData;

  return (
    <div className="glass-card p-6 mb-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <TrendingUp size={20} className="text-cyan-400" />
            Time-Series Traffic Volume & Attack Burst Resampling (Practical 7 & 8)
          </h2>
          <p className="text-xs text-slate-400">Daily resampled log volume across Benign vs Attack categories</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-semibold">
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" /> Benign
          </span>
          <span className="flex items-center gap-1.5 text-rose-400">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-400 inline-block" /> Brute Force
          </span>
          <span className="flex items-center gap-1.5 text-amber-400">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" /> SQLi
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" /> Path Traversal
          </span>
        </div>
      </div>

      <div className="h-72 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorBenign" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorBrute" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorSQLi" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 255, 255, 0.05)" />
            <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} />
            <YAxis stroke="#64748b" tick={{ fontSize: 11 }} scale="log" domain={['auto', 'auto']} allowDataOverflow />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderRadius: '12px',
                color: '#fff',
                fontSize: '12px',
              }}
            />
            <Area type="monotone" dataKey="brute_force" name="Brute Force" stroke="#f43f5e" fillOpacity={1} fill="url(#colorBrute)" strokeWidth={2} />
            <Area type="monotone" dataKey="benign" name="Benign" stroke="#10b981" fillOpacity={1} fill="url(#colorBenign)" strokeWidth={2} />
            <Area type="monotone" dataKey="sqli" name="SQL Injection" stroke="#f59e0b" fillOpacity={1} fill="url(#colorSQLi)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
