import React from 'react';
import { Globe, AlertTriangle } from 'lucide-react';

const mockTopIPs = [
  { ip: '212.60.12.161', requests: 612026, primary_vector: 'BRUTE_FORCE' },
  { ip: '103.111.33.197', requests: 310022, primary_vector: 'BRUTE_FORCE' },
  { ip: '157.32.35.29', requests: 273556, primary_vector: 'BRUTE_FORCE' },
  { ip: '152.58.35.97', requests: 259074, primary_vector: 'BRUTE_FORCE' },
  { ip: '199.188.238.77', requests: 115757, primary_vector: 'BRUTE_FORCE' },
  { ip: '185.220.101.4', requests: 4210, primary_vector: 'SQLI' },
  { ip: '45.155.205.111', requests: 1404, primary_vector: 'PATH_TRAVERSAL' },
];

export default function TopIPsTable({ ips }) {
  const tableData = ips && ips.length > 0 ? ips : mockTopIPs;

  return (
    <div className="glass-card p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Globe size={20} className="text-amber-400" />
            Top Attacking IP Source Ranking (Practical 7)
          </h2>
          <p className="text-xs text-slate-400">Aggregated IP traffic ranking and primary threat category</p>
        </div>
        <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-medium">Top {tableData.length} Sources</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-xs font-bold text-slate-400 uppercase tracking-wider">
              <th className="pb-3">Rank</th>
              <th className="pb-3">IP Address</th>
              <th className="pb-3">Total Requests</th>
              <th className="pb-3">Primary Threat Vector</th>
              <th className="pb-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-sm">
            {tableData.map((item, index) => {
              const vector = item.primary_vector?.toUpperCase() || 'BRUTE_FORCE';
              const badgeStyle =
                vector === 'SQLI' || vector === 'PATH_TRAVERSAL'
                  ? 'badge-critical'
                  : vector === 'BRUTE_FORCE'
                  ? 'badge-high'
                  : 'badge-low';

              return (
                <tr key={index} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3.5 font-bold text-slate-500">#{index + 1}</td>
                  <td className="py-3.5 font-mono font-semibold text-cyan-400">{item.ip}</td>
                  <td className="py-3.5 font-bold text-white">{item.requests.toLocaleString()}</td>
                  <td className="py-3.5">
                    <span className={`badge ${badgeStyle}`}>{vector}</span>
                  </td>
                  <td className="py-3.5 text-xs text-slate-400 flex items-center gap-1.5">
                    <AlertTriangle size={14} className="text-rose-400" /> Blocked
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
