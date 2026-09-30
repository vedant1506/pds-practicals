# PDS Practicals — CyberCop AI Security Log Analyzer

End-to-end cybersecurity log analysis suite: Python data pipeline (Practicals 1–10) + FastAPI backend + React/Vite dashboard. Ingest raw server logs, parse, clean, label attacks (SQLi / bots), engineer features, train ML models, and explore everything from an interactive UI.

## Features

- Raw log ingestion & structural exploration
- Heuristic log parsing to structured CSV
- Cleaning / preprocessing pipeline
- Attack labeling (bot taxonomy, SQLi taxonomy)
- Feature engineering (entropy, URL/request features)
- Train/test split + ML classification with evaluation plots
- FastAPI backend (`backend/app.py`) with upload, analysis & chat APIs
- React dashboard (`dashboard/`) with charts, KPIs, practicals syllabus
- Sample logs + pre-generated plots included

## Project structure

```
.
├── backend/            # FastAPI app (app.py)
├── dashboard/          # React + Vite frontend
├── scripts/            # practical_1.py … practical_10.py + helpers
│   ├── generate_sample_log.py
│   ├── bot_taxonomy.py / sqli_taxonomy.py
│   └── path_utils.py
├── notebooks/          # practical_1.ipynb … practical_10.ipynb
├── sample_logs/        # small committed sample logs
├── plots/              # generated charts (committed)
├── data/               # IGNORED — large generated CSVs/parquets
├── logs/               # IGNORED — large runtime logs
└── start_all.py        # run backend + frontend together
```

> `data/`, `backend/data/`, `logs/`, `node_modules/`, `dist/`, `__pycache__/`, `.env` are git-ignored. Regenerate datasets locally with the scripts below.

## Practicals

| # | Script | What it does |
|---|--------|--------------|
| 1 | `practical_1.py` | Raw log ingestion & structural exploration |
| 2 | `practical_2.py` | Heuristic parsing to structured data |
| 3 | `practical_3.py` | Data cleaning & preprocessing |
| 4 | `practical_4.py` | Request labeling (bot / SQLi taxonomies) |
| 5 | `practical_5.py` | Feature engineering |
| 6 | `practical_6.py` | Balancing & train/test split |
| 7 | `practical_7.py` | EDA / traffic analysis |
| 8 | `practical_8.py` | Attack analysis over time |
| 9 | `practical_9.py` | ML model training & comparison |
| 10 | `practical_10.py` | Log data pipeline (used by backend) |

Plus `advanced_ml_benchmark.py` for extended model/latency benchmarks.

## Quickstart

### 1. Clone

```bash
git clone https://github.com/vedant1506/pds-practicals.git
cd pds-practicals
```

### 2. Python pipeline

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pandas numpy matplotlib seaborn scikit-learn fastapi uvicorn tabulate

# Generate / use sample logs
python scripts/generate_sample_log.py

# Run practicals in order
python scripts/practical_1.py --headless
python scripts/practical_2.py --headless
# … through practical_9.py / practical_10.py
```

Or open `notebooks/practical_*.ipynb` in Jupyter.

### 3. Backend + Frontend (all services)

```bash
python start_all.py
```

- Backend API: http://localhost:8000 (docs at `/docs`)
- Frontend UI: http://localhost:5173

Run individually:

```bash
# Backend
cd backend && python app.py        # or: uvicorn app:app --reload

# Frontend
cd dashboard && npm install && npm run dev
```

### 4. Environment

Copy and fill secrets (never commit the real one):

```bash
cp .env.example .env   # if present, else create .env (see backend/app.py load_env_file)
```

## Tech stack

- Python, pandas, scikit-learn, matplotlib/seaborn, FastAPI
- React 19, Vite, Tailwind, Recharts

## Notes

- Large files (`data/`, `logs/cj.log`) are intentionally untracked — run the pipeline to recreate them.
- Plots in `plots/` and `dashboard/public/plots/` are pre-generated outputs for quick review.
