import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { ShieldCheck } from 'lucide-react';

const defaultStatusData = [
  { name: '403 Forbidden', value: 1426298, color: '#f43f5e' },
  { name: '404 Not Found', value: 397658, color: '#f59e0b' },
  { name: '200 OK', value: 237475, color: '#10b981' },
];

export default function StatusCodeChart({ statusData }) {
  const data = statusData && statusData.length > 0 ? statusData : defaultStatusData;

  return (
    <div className="glass-card p-6 flex flex-col justify-between">
      <div>
        <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-1">
          <ShieldCheck size={20} className="text-emerald-400" />
          HTTP Status Code Distribution (Practical 8)
        </h2>
        <p className="text-xs text-slate-400">Response status codes returned by web server</p>
      </div>

      <div className="h-60 w-full my-4">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={85}
              paddingAngle={5}
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color || '#06b6d4'} stroke="rgba(0,0,0,0.5)" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                borderColor: 'rgba(255,255,255,0.1)',
                borderRadius: '12px',
                color: '#fff',
                fontSize: '12px',
              }}
              formatter={(val) => `${val.toLocaleString()} logs`}
            />
            <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
