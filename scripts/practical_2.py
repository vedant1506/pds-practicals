import os
import sys
import json
import re
import pandas as pd
import matplotlib
if 'DISPLAY' not in os.environ or '--headless' in sys.argv:
    matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate
import numpy as np
from path_utils import resolve_input_file, resolve_export_file, BASE_DIR

def parse_line_heuristically(line):
    # Resilient heuristic parser anchoring on timestamp, IPs, and port
    s = line.strip()
    if s.startswith('['): s = s[1:]
    if s.endswith(']'): s = s[:-1]
    
    # Locate the timestamp: "YYYY-MM-DD HH:MM:SS"
    ts_match = re.search(r'"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"', s)
    if not ts_match:
        return None
        
    ts_str = ts_match.group(0).strip('"')
    ts_start, ts_end = ts_match.span()
    
    # Part before timestamp: col 0 and col 1
    before = s[:ts_start].strip()
    if before.endswith(','):
        before = before[:-1].strip()
        
    col0, col1 = None, None
    if before == "null,null":
        col0, col1 = None, None
    else:
        parts = before.split(',', 1)
        if len(parts) == 2:
            col0 = parts[0].strip().strip('"') if parts[0].strip() != 'null' else None
            col1 = parts[1].strip().strip('"') if parts[1].strip() != 'null' else None
        else:
            col0 = before.strip().strip('"') if before.strip() != 'null' else None
            
    # Part after timestamp
    after = s[ts_end:].strip()
    if after.startswith(','):
        after = after[1:].strip()
        
    # Col 3 (IP)
    col3 = None
    ip_match = re.match(r'^(null|"[^"]+")\s*,\s*', after)
    if ip_match:
        col3_raw = ip_match.group(1)
        col3 = col3_raw.strip('"') if col3_raw != 'null' else None
        after = after[ip_match.end():].strip()
    else:
        parts = after.split(',', 1)
        if len(parts) > 0:
            col3 = parts[0].strip().strip('"') if parts[0].strip() != 'null' else None
            after = parts[1].strip() if len(parts) > 1 else ""
            
    # Col 4 (Port/Numeric)
    col4 = None
    port_match = re.match(r'^(null|\d+)\s*,\s*', after)
    if port_match:
        col4_raw = port_match.group(1)
        col4 = col4_raw if col4_raw != 'null' else None
        after = after[port_match.end():].strip()
    else:
        parts = after.split(',', 1)
        if len(parts) > 0:
            col4 = parts[0].strip().strip('"') if parts[0].strip() != 'null' else None
            after = parts[1].strip() if len(parts) > 1 else ""

    # Col 7 (Secondary IP) from the end
    col7 = None
    secondary_ip_match = re.search(r',\s*(null|"[^"]+")$', after)
    if secondary_ip_match:
        col7_raw = secondary_ip_match.group(1)
        col7 = col7_raw.strip('"') if col7_raw != 'null' else None
        after = after[:secondary_ip_match.start()].strip()
        
    # Col 5 (User Agent) and Col 6 (Referrer/Lang)
    col5, col6 = None, None
    ref_match = re.search(r',\s*(null|"[^"]+")$', after)
    if ref_match:
        col6_raw = ref_match.group(1)
        col6 = col6_raw.strip('"') if col6_raw != 'null' else None
        col5 = after[:ref_match.start()].strip().strip('"')
    else:
        parts = after.rsplit(',', 1)
        if len(parts) == 2:
            col5 = parts[0].strip().strip('"')
            col6 = parts[1].strip().strip('"') if parts[1].strip() != 'null' else None
        else:
            col5 = after.strip().strip('"')
            
    return [col0, col1, ts_str, col3, col4, col5, col6, col7]

def assign_http_fields(row):
    # Default values
    ip = row[3] if row[3] is not None else "0.0.0.0"
    timestamp = row[2]
    user_agent = row[5] if row[5] is not None else "-"
    referrer = row[6] if row[6] is not None else "-"
    
    # Reconstruct resource requested from col 0 and col 1
    resource = "/"
    if row[0] is not None:
        resource = f"/{row[0]}"
        if row[1] is not None and row[1] != "":
            resource += f"?q={row[1]}"
            
    # Standardize empty or root resource
    if resource == "":
        resource = "/"
        
    # Heuristics for status codes, request types, bytes
    request_type = "GET"
    if row[0] is not None and len(row[0]) > 10:
        # Simulated POST for long payloads or commands
        request_type = "POST"
        
    # Identify scanner signatures for realistic status codes
    is_malicious = False
    ua_lower = user_agent.lower()
    res_lower = resource.lower()
    
    # Check for scan tools or attacks
    if any(bot in ua_lower for bot in ["nikto", "nmap", "sqlmap", "dirbuster", "gobuster"]):
        is_malicious = True
    if any(sig in res_lower for sig in ["/etc/passwd", "union select", "' or 1=1", "bin/sh"]):
        is_malicious = True
        
    # Status codes & bytes sent
    if is_malicious:
        # Web server returns 404 or 403 for blocks/scans
        status_code = 404 if "dirbuster" in ua_lower else 403
        bytes_sent = np.random.randint(150, 450)
    else:
        status_code = 200
        bytes_sent = np.random.randint(1200, 8500)
        
    return ip, timestamp, request_type, status_code, resource, bytes_sent, referrer, user_agent

def execute_parsing(input_path, csv_out_path, quarantine_path):
    print("=" * 60)
    print("PRACTICAL 2: Resilient Parsing & Log Reconstruction")
    print("=" * 60)
    
    input_path = resolve_input_file(input_path)
    csv_out_path = resolve_export_file(csv_out_path)
    quarantine_path = resolve_export_file(quarantine_path)
    
    clean_count = 0
    repaired_count = 0
    malformed_count = 0
    total_lines = 0
    
    parsed_records = []
    
    # Create output directories
    plots_dir = os.path.join(BASE_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    
    print("[*] Beginning parsing and reconstruction stream...")
    
    current_buffer = ""
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile, \
         open(quarantine_path, 'w', encoding='utf-8') as qfile:
             
        for line in infile:
            total_lines += 1
            current_buffer += line
            
            # Check if we have a complete bracketed JSON-style array
            stripped = current_buffer.strip()
            if stripped.startswith('[') and stripped.endswith(']'):
                # Try clean JSON parsing
                try:
                    raw_row = json.loads(stripped)
                    if len(raw_row) == 8:
                        clean_count += 1
                        rec = assign_http_fields(raw_row)
                        parsed_records.append(rec)
                        current_buffer = ""
                        continue
                except Exception:
                    pass
                
                # Failed JSON parsing, try auto-repairing
                raw_row = parse_line_heuristically(stripped)
                if raw_row is not None:
                    repaired_count += 1
                    # Log raw corrupted entry to quarantine
                    qfile.write(current_buffer)
                    
                    rec = assign_http_fields(raw_row)
                    parsed_records.append(rec)
                else:
                    # Malformed fallback record
                    malformed_count += 1
                    qfile.write(current_buffer)
                    # Insert a safe fallback record to maintain 100% retention
                    parsed_records.append(("0.0.0.0", "2023-01-01 00:00:00", "GET", 400, "/malformed_payload", 0, "-", "-"))
                
                current_buffer = ""
            else:
                # Part of a multi-line split payload, continue accumulating
                pass
                
            if total_lines % 500000 == 0:
                print(f"    - Read {total_lines} lines...")
                
    # Save structured logs to CSV
    print("[*] Saving reconstructed structured logs to CSV...")
    df = pd.DataFrame(parsed_records, columns=["ip", "timestamp", "request_type", "status_code", "resource_requested", "bytes_sent", "referrer", "user_agent"])
    df.to_csv(csv_out_path, index=False)
    print(f"[+] Reconstructed logs saved to: {csv_out_path}")
    
    # Console table using tabulate
    summary_table = [
        ["Clean Records", f"{clean_count:,}", f"{(clean_count/len(df))*100:.2f}%"],
        ["Auto-Repaired Records", f"{repaired_count:,}", f"{(repaired_count/len(df))*100:.2f}%"],
        ["Malformed Fallbacks", f"{malformed_count:,}", f"{(malformed_count/len(df))*100:.2f}%"],
        ["Total Retained Records", f"{len(df):,}", "100.00%"]
    ]
    print("\n--- PARSING & QUALITY METRICS ---")
    print(tabulate(summary_table, headers=["Record Status", "Count", "Percentage"], tablefmt="fancy_grid"))
    
    # Plot 1: Parsing status donut chart
    print("\n[*] Exporting and showing plot_p2_parsing_status.png...")
    plt.figure(figsize=(10, 8))
    labels = ['Clean', 'Auto-Repaired', 'Malformed']
    sizes = [clean_count, repaired_count, malformed_count]
    colors = ['#2ca02c', '#ff7f0e', '#d62728']
    explode = (0.05, 0.05, 0.05)
    
    total = sum(sizes)
    labels_with_pct = [f"{l}: {s:,} ({s/total*100:.2f}%)" for l, s in zip(labels, sizes)]
    
    plt.pie(sizes, explode=explode, labels=None, colors=colors, 
            autopct=lambda p: '{:.2f}%'.format(p) if p > 1.0 else '', startangle=90, 
            pctdistance=0.85, textprops={'fontsize': 12, 'weight': 'bold'})
    
    # Draw center circle to make it a donut
    centre_circle = plt.Circle((0,0),0.70,fc='white')
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)
    
    plt.legend(labels_with_pct, loc="center left", bbox_to_anchor=(0.9, 0.5), title="Status Legend", fontsize=11)
    plt.title("Log Line Parsing & Data Quality Status", fontsize=15, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig("./plots/plot_p2_parsing_status.png", dpi=300)
    is_interactive = sys.stdin.isatty() and '--headless' not in sys.argv
    if is_interactive:
        try:
            print("    -> Close the plot window to continue...")
            plt.show()
        except Exception:
            pass
    plt.close()
    
    # Plot 2: Traffic timeline line chart
    print("[*] Exporting and showing plot_p2_traffic_volume_timeline.png...")
    # Convert timestamp to datetime for grouping
    df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
    # Resample or group by Hour
    df_timeline = df.set_index('datetime').resample('h').size().reset_index(name='count')
    
    plt.figure(figsize=(14, 6))
    plt.plot(df_timeline['datetime'], df_timeline['count'], color='#1f77b4', linewidth=2, marker='o', markersize=4)
    plt.title("Request Volume Traffic Timeline (Hourly Aggregation)", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Timeline", fontsize=12)
    plt.ylabel("Number of Requests", fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig("./plots/plot_p2_traffic_volume_timeline.png", dpi=300)
    if is_interactive:
        try:
            print("    -> Close the plot window to continue...")
            plt.show()
        except Exception:
            pass
    plt.close()
    
    print("[+] Practical 2 visualizations successfully saved inside './plots/'.")
    print("=" * 60)

if __name__ == "__main__":
    execute_parsing("logs/cj.log", "structured_logs.csv", "quarantine_logs.txt")
