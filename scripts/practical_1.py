import os
import sys
import re
from collections import Counter
import pandas as pd
import matplotlib
if 'DISPLAY' not in os.environ or '--headless' in sys.argv:
    matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate
from path_utils import resolve_input_file, BASE_DIR

def analyze_raw_log(file_path):
    print("=" * 60)
    print("PRACTICAL 1: Raw Log Ingestion & Structural Exploration")
    print("=" * 60)
    
    file_path = resolve_input_file(file_path)
    
    # 1. Check file existence & size
    if not os.path.exists(file_path):
        print(f"Error: Log file not found at {file_path}")
        sys.exit(1)
        
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"[*] Raw log file detected: {file_path}")
    print(f"[*] File Size: {file_size_mb:.2f} MB")
    
    # Heuristic regex patterns
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    ts_pattern = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
    
    line_count = 0
    non_empty_count = 0
    line_lengths = []
    
    ip_counter = Counter()
    ts_counter = Counter()
    
    # Stream the file to process large sizes without memory crashes
    print("[*] Processing raw log lines in streaming mode...")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_count += 1
            stripped = line.strip()
            if stripped:
                non_empty_count += 1
                line_lengths.append(len(stripped))
                
                # Heuristic extraction
                ips = ip_pattern.findall(stripped)
                for ip in ips:
                    ip_counter[ip] += 1
                    
                ts_matches = ts_pattern.findall(stripped)
                for ts in ts_matches:
                    ts_counter[ts] += 1
                    
            if line_count % 500000 == 0:
                print(f"    - Processed {line_count} lines...")
                
    print("[+] Stream processing completed.")
    
    # Compute stats
    line_lengths_series = pd.Series(line_lengths)
    stats_summary = line_lengths_series.describe()
    
    # Print console summary using tabulate
    metrics_data = [
        ["Total Lines Count", f"{line_count:,}"],
        ["Non-Empty Lines Count", f"{non_empty_count:,}"],
        ["File Size (MB)", f"{file_size_mb:.2f} MB"],
        ["Average Line Length", f"{stats_summary['mean']:.2f}"],
        ["Min Line Length", f"{int(stats_summary['min'])}"],
        ["Max Line Length", f"{int(stats_summary['max'])}"],
        ["Unique IPs Found (Heuristics)", f"{len(ip_counter):,}"],
        ["Unique Timestamps Found", f"{len(ts_counter):,}"]
    ]
    print("\n--- FILE-LEVEL METRICS & STATS ---")
    print(tabulate(metrics_data, headers=["Metric", "Value"], tablefmt="fancy_grid"))
    
    # Print Top 15 IPs
    top_ips = ip_counter.most_common(15)
    print("\n--- TOP 15 MOST ACTIVE IPs (RAW HEURISTICS) ---")
    print(tabulate(top_ips, headers=["IP Address", "Occurrences"], tablefmt="fancy_grid"))
    
    # 2. Ensure plots directory exists
    plots_dir = os.path.join(BASE_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    
    # Set aesthetics styling
    plt.style.use('seaborn-v0_8')
    
    # Plot 1: Line length distribution histogram + KDE
    print("\n[*] Exporting and showing plot_p1_line_length_dist.png...")
    plt.figure(figsize=(10, 6))
    sns.histplot(line_lengths_series, bins=100, kde=True, color='#1f77b4', edgecolor='black', alpha=0.7)
    plt.title("Raw Log Line Length Variance & Distribution", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Line Length (Characters)", fontsize=12)
    plt.ylabel("Frequency", fontsize=12)
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, "plot_p1_line_length_dist.png"), dpi=300)
    is_interactive = sys.stdin.isatty() and '--headless' not in sys.argv
    if is_interactive:
        try:
            print("    -> Close the plot window to continue...")
            plt.show()
        except Exception:
            pass
    plt.close()
    
    # Plot 2: Top 15 most active source IP addresses
    print("[*] Exporting and showing plot_p1_top_raw_ips.png...")
    plt.figure(figsize=(12, 6))
    ip_df = pd.DataFrame(top_ips, columns=["IP", "Count"])
    sns.barplot(data=ip_df, x="Count", y="IP", hue="IP", palette="viridis", legend=False)
    plt.title("Top 15 Most Active Source IP Addresses (Heuristic Count)", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Request Count", fontsize=12)
    plt.ylabel("Source IP Address", fontsize=12)
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, "plot_p1_top_raw_ips.png"), dpi=300)
    if is_interactive:
        try:
            print("    -> Close the plot window to continue...")
            plt.show()
        except Exception:
            pass
    plt.close()
    
    print("[+] Visualizations exported successfully inside './plots/'.")
    print("=" * 60)

if __name__ == "__main__":
    analyze_raw_log("logs/cj.log")
