import React, { useState } from 'react';
import { BookOpen, CheckCircle2, Code2, FileText, BarChart2 } from 'lucide-react';

const practicalList = [
  {
    id: 1,
    title: 'Practical 1: Raw Log Ingestion & Structural Exploration',
    aim: 'To read a log file, calculate line counts, non-empty lines, and compute line length distribution.',
    script: 'practical_1.py',
    notebook: 'practical_1.ipynb',
    output: 'plot_p1_line_length_dist.png',
    metrics: 'Total lines: 2,061,431 | Non-empty lines: 2,061,431 | Avg line length: 147 chars',
  },
  {
    id: 2,
    title: 'Practical 2: Structured Log Parsing & Regex Decoding',
    aim: 'To parse unstructured log lines into tabular schema (IP, Timestamp, Method, URL, Status, Bytes, User-Agent).',
    script: 'practical_2.py',
    notebook: 'practical_2.ipynb',
    output: 'data/processed/structured_logs.csv',
    metrics: 'Parsing Success Rate: 100% (2,061,431 records extracted cleanly)',
  },
  {
    id: 3,
    title: 'Practical 3: Quality Assurance & Data Cleaning',
    aim: 'To clean dataset by deduplicating, standardizing datetime ISO formats, and quarantining invalid lines.',
    script: 'practical_3.py',
    notebook: 'practical_3.ipynb',
    output: 'data/processed/cleaned_logs.csv',
    metrics: 'Cleaned records: 2,061,431 | Quarantined corrupted records: 0',
  },
  {
    id: 4,
    title: 'Practical 4: Rule-Based Security Attack Labeling',
    aim: 'To categorize traffic using security heuristics (BENIGN, BRUTE_FORCE, SQLI, PATH_TRAVERSAL).',
    script: 'practical_4.py',
    notebook: 'practical_4.ipynb',
    output: 'data/processed/labeled_logs.csv',
    metrics: 'Brute-Force: 1,822,156 (88.39%) | Benign: 234,892 | SQLi: 2,979 | Traversal: 1,404',
  },
  {
    id: 5,
    title: 'Practical 5: Security Feature Engineering',
    aim: 'To compute request frequencies, inter-arrival time intervals, 404 status totals, bot flags, and URL entropy.',
    script: 'practical_5.py',
    notebook: 'practical_5.ipynb',
    output: 'data/processed/engineered_features.csv',
    metrics: '5 engineered numerical features computed for machine learning input',
  },
  {
    id: 6,
    title: 'Practical 6: Stratified Sampling & SMOTE Class Balancing',
    aim: 'To split dataset 80/20 stratified and apply Synthetic Minority Oversampling Technique (SMOTE).',
    script: 'practical_6.py',
    notebook: 'practical_6.ipynb',
    output: 'data/split/train_dataset.csv',
    metrics: 'Balanced Training Set: 200,000 balanced records | Capped at 50k per class',
  },
  {
    id: 7,
    title: 'Practical 7: Data Wrangling & Resampling Analysis',
    aim: 'To filter internal IPs & bot traffic, group by IP address, resample hourly time-series, and construct pivot tables.',
    script: 'practical_7.py',
    notebook: 'practical_7.ipynb',
    output: 'plot_p7_hourly_traffic.png',
    metrics: 'Top Attacking IP: 212.60.12.161 (612,026 requests) | Non-bot records: 238,810',
  },
  {
    id: 8,
    title: 'Practical 8: Visual Exploratory Data Analysis (EDA)',
    aim: 'To generate 5 EDA charts: hourly traffic, top 10 IPs, category timelines, status code distribution, heatmap.',
    script: 'practical_8.py',
    notebook: 'practical_8.ipynb',
    output: '5 Exported PNG Charts in ./plots/',
    metrics: 'Visual charts saved to high-resolution PNG files',
  },
  {
    id: 9,
    title: 'Practical 9: Machine Learning Classifier Models',
    aim: 'To train and evaluate Logistic Regression and Random Forest models for attack detection.',
    script: 'practical_9.py',
    notebook: 'practical_9.ipynb',
    output: 'plot_p9_confusion_matrices.png',
    metrics: 'Random Forest Accuracy: 99.34% | Weighted F1-Score: 99.53%',
  },
  {
    id: 10,
    title: 'Practical 10: Reusable Automated Log Data Pipeline',
    aim: 'To construct an OOP LogDataPipeline wrapping ingestion, parsing, cleaning, feature export, and online ML inference.',
    script: 'practical_10.py',
    notebook: 'practical_10.ipynb',
    output: 'processed_log_pipeline_output.parquet',
    metrics: 'Dual format export: CSV (20.97 MB) & Parquet (1.78 MB - 11.8x compression ratio)',
  },
];

export default function PracticalsSyllabus() {
  const [selectedP, setSelectedP] = useState(practicalList[8]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
      {/* Sidebar List */}
      <div className="glass-card p-4 space-y-2">
        <h2 className="text-sm font-bold text-slate-400 uppercase tracking-wider px-3 mb-3">
          Lab Manual Syllabus (Practicals 1–10)
        </h2>
        {practicalList.map((item) => (
          <button
            key={item.id}
            onClick={() => setSelectedP(item)}
            className={`w-full text-left p-3 rounded-xl transition-all duration-200 flex items-center justify-between text-xs font-semibold ${
              selectedP.id === item.id
                ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-white border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/40'
            }`}
          >
            <span className="truncate pr-2">Practical {item.id}</span>
            <CheckCircle2 size={14} className={selectedP.id === item.id ? 'text-cyan-400' : 'opacity-30'} />
          </button>
        ))}
      </div>

      {/* Detail Inspector */}
      <div className="lg:col-span-2 glass-card p-6 space-y-6">
        <div>
          <span className="badge badge-low mb-2">PDS Lab Syllabus Requirement</span>
          <h2 className="text-xl font-extrabold text-white">{selectedP.title}</h2>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Aim / Objective:</h3>
          <p className="text-sm text-slate-300">{selectedP.aim}</p>
        </div>

        <div className="grid grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5 font-bold">
              <Code2 size={14} className="text-cyan-400" /> Executable Script:
            </span>
            <span className="font-mono text-cyan-300 font-semibold">{selectedP.script}</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5 font-bold">
              <FileText size={14} className="text-purple-400" /> Jupyter Notebook:
            </span>
            <span className="font-mono text-purple-300 font-semibold">{selectedP.notebook}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
            <BarChart2 size={14} /> Empirical Key Results & Metrics:
          </h3>
          <p className="text-sm font-mono text-white">{selectedP.metrics}</p>
        </div>
      </div>
    </div>
  );
}
