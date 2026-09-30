import os
import sys
import re
import json
import argparse
import math
import numpy as np
import pandas as pd
from tabulate import tabulate
from sklearn.ensemble import RandomForestClassifier
from path_utils import resolve_input_file, resolve_export_file, BASE_DIR

class LogDataPipeline:
    """
    Automated Reusable Data Pipeline for Web Server Log Analysis & Attack Detection.
    Stages:
    1. Ingestion: Reads raw log files (JSON array format, Apache access log, or CSV).
    2. Parsing: Extracts IP, Timestamp, HTTP Method, URL Path, Status Code, Bytes, User-Agent.
    3. Cleaning: Handling missing values, standardizing timestamps, deduplication.
    4. Labeling: Rule-based attack tagging (BENIGN, BRUTE_FORCE, SQLI, PATH_TRAVERSAL).
    5. Feature Engineering: Windowed IP counters, time intervals, status flags, entropy.
    6. Export: Saving pipeline artifacts to CSV and Apache Parquet.
    7. Machine Learning Inference: Predicting attack categories on fresh log inputs.
    """

    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status_code>\d{3})\s+(?P<response_bytes>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )

    def __init__(self, log_filepath="data.log"):
        self.log_filepath = resolve_input_file(log_filepath)
        self.raw_df = None
        self.clean_df = None
        self.engineered_df = None
        self.model = None

    def ingest_and_parse(self, sample_limit=None):
        if not os.path.exists(self.log_filepath):
            for fallback in ["logs/cj.log", "structured_logs.csv", "cleaned_logs.csv"]:
                cand = resolve_input_file(fallback)
                if os.path.exists(cand):
                    self.log_filepath = cand
                    break

        print(f"[*] Pipeline Stage 1: Ingesting & Parsing log file from '{self.log_filepath}'...")
        if not os.path.exists(self.log_filepath):
            raise FileNotFoundError(f"Log file '{self.log_filepath}' not found.")

        # Scenario A: Structured CSV input
        if self.log_filepath.endswith('.csv'):
            self.raw_df = pd.read_csv(self.log_filepath, nrows=sample_limit)
            print(f"[+] Loaded {len(self.raw_df):,} structured log records from CSV.")
            return self.raw_df

        # Scenario B: Raw Log streaming input (JSON line / Apache standard format)
        parsed_records = []
        with open(self.log_filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if sample_limit and i >= sample_limit:
                    break
                s = line.strip()
                if not s:
                    continue

                # Try parsing JSON array format (e.g. cj.log: [null, null, "2023-01-08 08:07:15", "104.28.209.153", ...])
                if s.startswith('[') and s.endswith(']'):
                    try:
                        arr = json.loads(s)
                        if isinstance(arr, list) and len(arr) >= 6:
                            parsed_records.append({
                                'ip': str(arr[3]) if arr[3] is not None else '0.0.0.0',
                                'timestamp': str(arr[2]) if arr[2] is not None else '1970-01-01 00:00:00',
                                'request_type': 'GET',
                                'url_path': '/' if len(arr) < 9 or arr[8] is None else str(arr[8]),
                                'status_code': 200,
                                'response_bytes': 0,
                                'user_agent': str(arr[5]) if len(arr) > 5 and arr[5] is not None else 'UNKNOWN'
                            })
                            continue
                    except Exception:
                        pass

                # Try Standard Apache Log Regex match
                match = self.LOG_PATTERN.match(s)
                if match:
                    dict_data = match.groupdict()
                    req = dict_data.get('request', '')
                    parts = req.split(' ')
                    req_type = parts[0] if len(parts) > 0 else 'UNKNOWN'
                    url_path = parts[1] if len(parts) > 1 else '/'
                    parsed_records.append({
                        'ip': dict_data['ip'],
                        'timestamp': dict_data['timestamp'],
                        'request_type': req_type,
                        'url_path': url_path,
                        'status_code': int(dict_data['status_code']),
                        'response_bytes': 0 if dict_data['response_bytes'] == '-' else int(dict_data['response_bytes']),
                        'user_agent': dict_data['user_agent']
                    })

        self.raw_df = pd.DataFrame(parsed_records)
        print(f"[+] Successfully parsed {len(self.raw_df):,} log entries into DataFrame.")
        return self.raw_df

    def clean_data(self):
        print("\n[*] Pipeline Stage 2: Data Cleaning & Preprocessing...")
        if self.raw_df is None or self.raw_df.empty:
            raise ValueError("Raw log DataFrame is empty. Run ingest_and_parse() first.")

        df = self.raw_df.copy()

        # Deduplicate exact duplicate rows
        initial_count = len(df)
        df = df.drop_duplicates().reset_index(drop=True)
        dedup_count = len(df)
        print(f"    - Removed {initial_count - dedup_count:,} duplicate records.")

        # Standardize timestamp to datetime format
        if 'timestamp_dt' not in df.columns:
            df['timestamp_dt'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
            if df['timestamp_dt'].isna().all():
                df['timestamp_dt'] = pd.to_datetime(df['timestamp'], format='mixed', errors='coerce')
        
        # Keep records (fill NAT if any)
        df['timestamp_dt'] = df['timestamp_dt'].fillna(pd.Timestamp.now())
        df = df.sort_values(by='timestamp_dt').reset_index(drop=True)

        # Standardize HTTP request methods
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        df['request_type'] = df['request_type'].astype(str).str.upper()
        df['request_type'] = df['request_type'].apply(lambda x: x if x in valid_methods else 'OTHER')

        # Fill missing user agents
        df['user_agent'] = df['user_agent'].fillna('UNKNOWN').astype(str)

        self.clean_df = df
        print(f"[+] Data Cleaning complete. Total clean records: {len(self.clean_df):,}")
        return self.clean_df

    def rule_based_labeling(self):
        print("\n[*] Pipeline Stage 3: Rule-Based Attack Labeling...")
        if self.clean_df is None:
            raise ValueError("Clean DataFrame missing. Run clean_data() first.")

        df = self.clean_df.copy()

        # If dataset already contains 'label', preserve it unless re-labeling needed
        if 'label' not in df.columns:
            def label_log_entry(row):
                url = str(row.get('url_path', '')).lower()
                ua = str(row.get('user_agent', '')).lower()
                status = row.get('status_code', 200)

                # SQL Injection Rules
                sqli_keywords = ['union', 'select', 'insert', 'drop', 'concat', 'char(', '--', '%27', "'", '1=1', 'or 1=1']
                if any(k in url for k in sqli_keywords):
                    return 'SQLI'

                # Path Traversal Rules
                path_keywords = ['../', '..\\', '%2e%2e', '/etc/passwd', 'c:\\', 'cmd.exe', 'win.ini']
                if any(k in url for k in path_keywords):
                    return 'PATH_TRAVERSAL'

                # Brute Force / Scanning Rules (High volume 403/404 or specific bots)
                if status == 403 or (status == 404 and 'bot' in ua):
                    return 'BRUTE_FORCE'

                return 'BENIGN'

            df['label'] = df.apply(label_log_entry, axis=1)

        self.clean_df = df
        print("[+] Rule-based attack labeling applied successfully.")
        return self.clean_df

    @staticmethod
    def calculate_entropy(text):
        if not isinstance(text, str) or not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log2(p) for p in prob])

    def engineer_features(self):
        print("\n[*] Pipeline Stage 4: Feature Engineering & Aggregation...")
        if self.clean_df is None:
            raise ValueError("Labeled DataFrame missing. Run rule_based_labeling() first.")

        df = self.clean_df.copy()

        # 1. Frequency of requests per IP
        if 'ip_request_count' not in df.columns:
            ip_counts = df['ip'].value_counts()
            df['ip_request_count'] = df['ip'].map(ip_counts)

        # 2. Time difference between consecutive requests from same IP (seconds)
        if 'time_diff_seconds' not in df.columns:
            df['time_diff_seconds'] = df.groupby('ip')['timestamp_dt'].diff().dt.total_seconds().fillna(0)

        # 3. Accumulated 404 count per IP
        if 'status_code_404_count' not in df.columns:
            df['is_404'] = (df['status_code'] == 404).astype(int)
            df['status_code_404_count'] = df.groupby('ip')['is_404'].transform('sum')

        # 4. Bot User-Agent Indicator
        if 'is_bot_agent' not in df.columns:
            bot_keywords = ['bot', 'crawler', 'spider', 'python', 'curl', 'wget', 'nikto', 'sqlmap', 'nmap', 'hydra']
            df['is_bot_agent'] = df['user_agent'].str.lower().apply(lambda ua: 1 if any(b in ua for b in bot_keywords) else 0)

        # 5. URL Path Entropy
        if 'url_entropy' not in df.columns:
            df['url_entropy'] = df['url_path'].apply(self.calculate_entropy)

        self.engineered_df = df
        print(f"[+] Feature Engineering complete across {len(self.engineered_df):,} entries.")
        return self.engineered_df

    def save_pipeline_output(self, csv_filepath="processed_log_pipeline_output.csv", parquet_filepath="processed_log_pipeline_output.parquet"):
        print("\n[*] Pipeline Stage 5: Exporting Processed Data Artifacts...")
        if self.engineered_df is None:
            raise ValueError("Engineered DataFrame missing. Run engineer_features() first.")

        csv_filepath = resolve_export_file(csv_filepath)
        parquet_filepath = resolve_export_file(parquet_filepath)

        export_cols = [c for c in ['ip', 'timestamp', 'request_type', 'url_path', 'status_code', 'user_agent',
                       'ip_request_count', 'time_diff_seconds', 'status_code_404_count', 'is_bot_agent', 'url_entropy', 'label'] if c in self.engineered_df.columns]

        output_df = self.engineered_df[export_cols]

        # Save to CSV
        output_df.to_csv(csv_filepath, index=False)
        print(f"    [+] Saved CSV Pipeline Artifact: '{csv_filepath}' ({os.path.getsize(csv_filepath)/1e6:.2f} MB)")

        # Save to Apache Parquet format
        try:
            output_df.to_parquet(parquet_filepath, index=False)
            print(f"    [+] Saved Parquet Pipeline Artifact: '{parquet_filepath}' ({os.path.getsize(parquet_filepath)/1e6:.2f} MB)")
        except Exception as e:
            print(f"    [!] Warning: Parquet export skipped ({e}). Install pyarrow/fastparquet.")

        return csv_filepath, parquet_filepath

    def train_and_run_inference(self, train_file="train_dataset.csv"):
        print("\n[*] Pipeline Stage 6: Machine Learning Attack Classification Inference...")
        resolved_train = resolve_input_file(train_file)
        if not os.path.exists(resolved_train):
            print(f"    [!] Training file '{train_file}' not found. Skipping ML classification.")
            return None

        train_df = pd.read_csv(resolved_train)
        feature_cols = ['ip_request_count', 'time_diff_seconds', 'status_code_404_count', 'is_bot_agent', 'url_entropy']

        X_train, y_train = train_df[feature_cols], train_df['label']
        print(f"    - Training Random Forest Classifier on {len(X_train):,} reference samples...")
        self.model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)

        X_inference = self.engineered_df[feature_cols]
        print(f"    - Running automated attack predictions on {len(X_inference):,} current pipeline records...")
        predictions = self.model.predict(X_inference)
        self.engineered_df['ml_predicted_label'] = predictions

        print("\n--- PIPELINE AUTOMATED ML PREDICTION SUMMARY ---")
        pred_counts = pd.Series(predictions).value_counts().reset_index()
        pred_counts.columns = ['Predicted Class', 'Count']
        pred_counts['Percentage'] = (pred_counts['Count'] / len(predictions) * 100).map("{:.2f}%".format)
        print(tabulate(pred_counts, headers=['Predicted Class', 'Record Count', 'Share (%)'], tablefmt="fancy_grid"))

        return predictions

    def run_full_pipeline(self, output_csv="processed_log_pipeline_output.csv", output_parquet="processed_log_pipeline_output.parquet"):
        print("=" * 60)
        print("PRACTICAL 10: Reusable Automated Log Processing Pipeline")
        print("=" * 60)

        self.ingest_and_parse()
        self.clean_data()
        self.rule_based_labeling()
        self.engineer_features()
        self.save_pipeline_output(csv_filepath=output_csv, parquet_filepath=output_parquet)
        self.train_and_run_inference()

        print("\n[+] Full Pipeline Execution Completed Successfully!")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Practical 10: Reusable Data Pipeline for Log File Processing.")
    parser.add_argument("--input", default="data.log", help="Path to input raw log file (default: data.log)")
    parser.add_argument("--output_csv", default="processed_log_pipeline_output.csv", help="Path to output CSV file")
    parser.add_argument("--output_parquet", default="processed_log_pipeline_output.parquet", help="Path to output Parquet file")

    args = parser.parse_args()

    pipeline = LogDataPipeline(log_filepath=args.input)
    pipeline.run_full_pipeline(output_csv=args.output_csv, output_parquet=args.output_parquet)


if __name__ == "__main__":
    main()
