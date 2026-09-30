import os
import sys
import math
import pandas as pd
import numpy as np
import matplotlib
if 'DISPLAY' not in os.environ or '--headless' in sys.argv:
    matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate
from path_utils import resolve_input_file, resolve_export_file, BASE_DIR
from bot_taxonomy import classify_bot
from sqli_taxonomy import classify_sqli

def calculate_entropy(text):
    """Calculates the Shannon Entropy (randomness score) of a given text string."""
    if not text or pd.isna(text):
        return 0.0
    text_str = str(text)
    prob = [float(text_str.count(c)) / len(text_str) for c in set(text_str)]
    return -sum([p * math.log2(p) for p in prob])

def generate_features(input_file="labeled_logs.csv", output_file="engineered_features.csv"):
    print("=" * 60)
    print("PRACTICAL 5: Feature Engineering for Anomaly Detection")
    print("=" * 60)
    
    resolved_input = resolve_input_file(input_file)
    resolved_output = resolve_export_file(output_file)
    
    # 1. Load labeled dataset
    print(f"[*] Loading dataset from '{resolved_input}'...")
    try:
        df = pd.read_csv(resolved_input, low_memory=False)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please run Practical 4 first.")
        sys.exit(1)
        
    print(f"[+] Total Records Loaded: {len(df):,}")
    
    # Ensure timestamp is datetime and sort
    print("\n[*] Sorting dataset by IP address and timestamp...")
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.sort_values(by=['ip', 'timestamp']).reset_index(drop=True)
    
    # Feature 1: IP Request Count
    print("[Feature 1/5] Calculating total requests per IP address...")
    ip_counts = df['ip'].value_counts()
    df['ip_request_count'] = df['ip'].map(ip_counts)
    
    # Feature 2: Time Gap between consecutive requests
    print("[Feature 2/5] Calculating time gap between consecutive requests per IP...")
    df['time_diff_seconds'] = df.groupby('ip')['timestamp'].diff().dt.total_seconds().fillna(0.0)
    
    # Feature 3: Status code 404 frequency per IP
    print("[Feature 3/5] Calculating 404 status code frequency per IP...")
    if 'status_code' in df.columns:
        df['is_404'] = (df['status_code'] == 404).astype(int)
    else:
        df['is_404'] = 0
    df['status_code_404_count'] = df.groupby('ip')['is_404'].transform('sum')
    df.drop(columns=['is_404'], inplace=True)
    
    # Feature 4: Bot Agent Detection
    print("[Feature 4/5] Parsing User-Agent signatures (Bot vs Human)...")
    bot_keywords = r"(?:bot|crawler|spider|scraper|sqlmap|nikto|gobuster|dirbuster|curl|python-urllib|nmap)"
    df['is_bot_agent'] = df['user_agent'].astype(str).str.contains(bot_keywords, regex=True, case=False).astype(int)
    
    # Feature 5: URL Entropy
    print("[Feature 5/5] Calculating URL Entropy using Lookup Table...")
    unique_urls = df['resource_requested'].astype(str).unique()
    entropy_dict = {url: calculate_entropy(url) for url in unique_urls}
    df['url_entropy'] = df['resource_requested'].astype(str).map(entropy_dict)
    
    # Display summary of engineered features
    feature_cols = ['ip_request_count', 'time_diff_seconds', 'status_code_404_count', 'is_bot_agent', 'url_entropy']

    # Metadata (NOT an ML feature): which tool? Carried forward from Practical 4
    # if present, else derived via the shared taxonomy. Kept out of feature_cols
    # so Practicals 6-9 models are unaffected.
    if 'bot_family' not in df.columns and 'user_agent' in df.columns:
        print("[Metadata] Deriving bot_family (attacking tool) via shared taxonomy...")
        df['bot_family'] = df['user_agent'].astype(str).map(classify_bot)
    if 'sqli_variant' not in df.columns and 'label' in df.columns and 'resource_requested' in df.columns:
        print("[Metadata] Deriving sqli_variant (payload technique) via shared taxonomy...")
        df['sqli_variant'] = '-'
        is_sqli = df['label'].astype(str).str.lower() == 'sqli'
        df.loc[is_sqli, 'sqli_variant'] = df.loc[is_sqli, 'resource_requested'].astype(str).map(classify_sqli)
    
    print("\n--- FEATURE STATISTICS SUMMARY ---")
    stats_df = df[feature_cols].describe().T[['mean', 'std', 'min', '50%', 'max']]
    stats_df.columns = ['Mean', 'Std Dev', 'Min', 'Median', 'Max']
    print(tabulate(stats_df, headers='keys', tablefmt='fancy_grid'))
    
    # Save output
    df.to_csv(resolved_output, index=False)
    print(f"\n[+] Saved feature-engineered dataset to '{resolved_output}'!")

    # Export Plot (disabled for viva - set True to re-enable)
    GENERATE_PLOTS = False
    if GENERATE_PLOTS:
        plots_dir = os.path.join(BASE_DIR, "plots")
        os.makedirs(plots_dir, exist_ok=True)
        plt.style.use('seaborn-v0_8')

        print("\n[*] Exporting and showing plot_p5_feature_distributions.png...")
        plt.figure(figsize=(12, 8))
        for i, col in enumerate(feature_cols, 1):
            plt.subplot(2, 3, i)
            sns.histplot(df[col], bins=30, kde=False, color='#1f77b4', edgecolor='black')
            plt.title(f"Distribution: {col}", fontsize=11, fontweight='bold')
            plt.tight_layout()

        plt.savefig(os.path.join(plots_dir, "plot_p5_feature_distributions.png"), dpi=300)

        is_interactive = sys.stdin.isatty() and '--headless' not in sys.argv
        if is_interactive:
            try:
                print("    -> Close the plot window to continue...")
                plt.show()
            except Exception:
                pass
        plt.close()
    else:
        print("\n[*] Plot generation skipped (GENERATE_PLOTS=False).")
    print("=" * 60)

if __name__ == "__main__":
    generate_features("labeled_logs.csv", "engineered_features.csv")
