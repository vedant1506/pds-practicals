import React from 'react';
import { Database, ShieldAlert, AlertTriangle, Globe, Lock } from 'lucide-react';

export default function KPICards({ stats }) {
  const cards = [
    {
      title: 'Total Logs Ingested',
      value: stats?.total_logs ? stats.total_logs.toLocaleString() : '2,061,431',
      subtitle: 'Parsed from cj.log',
      icon: Database,
      color: 'from-blue-500/20 to-cyan-500/10',
      border: 'border-cyan-500/30',
      textColor: 'text-cyan-400',
    },
    {
      title: 'Threat Detection Ratio',
      value: stats?.threat_percentage || '88.61%',
      subtitle: 'Attack Traffic Detected',
      icon: ShieldAlert,
      color: 'from-rose-500/20 to-pink-500/10',
      border: 'border-rose-500/30',
      textColor: 'text-rose-400',
    },
    {
      title: 'Top Threat Source IP',
      value: stats?.top_threat_ip || '212.60.12.161',
      subtitle: '612,026 Requests Blocked',
      icon: Globe,
      color: 'from-amber-500/20 to-orange-500/10',
      border: 'border-amber-500/30',
      textColor: 'text-amber-400',
    },
    {
      title: 'Active Attack Vectors',
      value: stats?.active_threat_types || '3 Vectors',
      subtitle: 'Brute-Force, SQLi, Traversal',
      icon: Lock,
      color: 'from-purple-500/20 to-indigo-500/10',
      border: 'border-purple-500/30',
      textColor: 'text-purple-400',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`glass-card p-5 bg-gradient-to-br ${card.color} ${card.border} flex items-center justify-between`}
          >
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">{card.title}</p>
              <h3 className="text-2xl font-extrabold text-white tracking-tight">{card.value}</h3>
              <p className="text-xs text-slate-400 mt-1">{card.subtitle}</p>
            </div>
            <div className={`p-3.5 rounded-2xl bg-slate-900/80 border border-slate-800 ${card.textColor}`}>
              <Icon size={24} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
