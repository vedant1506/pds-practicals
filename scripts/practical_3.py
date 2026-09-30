import os
import sys
import pandas as pd
import matplotlib
if 'DISPLAY' not in os.environ or '--headless' in sys.argv:
    matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate
from path_utils import resolve_input_file, resolve_export_file, BASE_DIR

def clean_and_preprocess_logs(input_file, output_file="cleaned_logs.csv"):
    print("=" * 60)
    print("PRACTICAL 3: Data Cleaning and Preprocessing")
    print("=" * 60)
    
    resolved_input = resolve_input_file(input_file)
    resolved_output = resolve_export_file(output_file)
    
    # 1. Load structured dataset
    print(f"[*] Loading dataset from '{resolved_input}'...")
    try:
        df = pd.read_csv(resolved_input, low_memory=False)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please run Practical 2 first.")
        sys.exit(1)
        
    initial_count = len(df)
    print(f"[+] Initial Total Rows Loaded: {initial_count:,}")
    
    # 2. Convert timestamp safely
    print("\n[Step 1] Converting 'timestamp' column to Datetime format...")
    if 'timestamp' in df.columns:
        df['timestamp'] = df['timestamp'].astype(str).str.replace('"', '').str.strip()
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        invalid_count = df['timestamp'].isna().sum()
        if invalid_count > 0:
            print(f"  ⚠️ Warning: {invalid_count:,} timestamps could not be parsed. Filling with default.")
            df['timestamp'] = df['timestamp'].fillna(pd.Timestamp('2023-01-08 00:00:00'))
            
    # 3. Clean string columns and missing values
    print("[Step 2] Cleaning missing values and normalizing text...")
    df.replace(['null', 'NaN', 'nan', 'None', '-'], pd.NA, inplace=True)
    
    text_columns = ['resource_requested', 'user_agent', 'referrer', 'request_type']
    for col in text_columns:
        if col in df.columns:
            df[col] = df[col].fillna('unknown').astype(str).str.lower().str.strip()
            
    if 'ip' in df.columns:
        df['ip'] = df['ip'].fillna('0.0.0.0').astype(str).str.strip()
        
    # 4. Normalize URL paths
    print("[Step 3] Normalizing URL paths...")
    if 'resource_requested' in df.columns:
        df['resource_requested'] = df['resource_requested'].str.rstrip('/')
        df['resource_requested'] = df['resource_requested'].str.replace(r'\.html$', '', regex=True)
        # Ensure root resource is represented properly
        df.loc[df['resource_requested'] == '', 'resource_requested'] = '/'
        
    # 5. Export cleaned logs
    df.to_csv(resolved_output, index=False)
    print(f"[+] Saved cleaned dataset to '{resolved_output}'!")
    
    # Summary of changes
    cleaned_count = len(df)
    print(f"\n✅ Data Cleaning Complete! Retained {cleaned_count:,} out of {initial_count:,} rows.")
    
    # 6. Generate visualization
    os.makedirs("./plots", exist_ok=True)
    plt.style.use('seaborn-v0_8')
    
    print("\n[*] Exporting and showing plot_p3_status_codes.png...")
    plt.figure(figsize=(10, 6))
    if 'status_code' in df.columns:
        status_counts = df['status_code'].value_counts()
        sns.barplot(x=status_counts.index, y=status_counts.values, palette='viridis', hue=status_counts.index, legend=False)
        plt.title("Distribution of HTTP Status Codes in Cleaned Logs", fontsize=14, fontweight='bold', pad=15)
        plt.xlabel("HTTP Status Code", fontsize=12)
        plt.ylabel("Request Count", fontsize=12)
        plt.yscale('log') # Use log scale because 200s will dominate
        for i, val in enumerate(status_counts.values):
            plt.text(i, val * 1.1, f"{val:,}", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    plt.savefig("./plots/plot_p3_status_codes.png", dpi=300)
    
    is_interactive = sys.stdin.isatty() and '--headless' not in sys.argv
    if is_interactive:
        try:
            print("    -> Close the plot window to continue...")
            plt.show()
        except Exception:
            pass
    plt.close()
    
    print("\n--- Cleaned DataFrame Info ---")
    df.info()
    
    print("\n--- First 5 Rows of Cleaned Dataset ---")
    print(tabulate(df.head(), headers='keys', tablefmt='fancy_grid'))
    print("=" * 60)

if __name__ == "__main__":
    clean_and_preprocess_logs("structured_logs.csv")
