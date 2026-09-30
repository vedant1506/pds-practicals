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
from bot_taxonomy import classify_bot, family_label, BOT_LABEL_PATTERN
from sqli_taxonomy import classify_sqli, variant_label

def label_log_requests(input_file="cleaned_logs.csv", output_file="labeled_logs.csv"):
    print("=" * 60)
    print("PRACTICAL 4: Request Labeling & Classification")
    print("=" * 60)
    
    resolved_input = resolve_input_file(input_file)
    resolved_output = resolve_export_file(output_file)
    
    # 1. Load the cleaned dataset from Practical 3
    print(f"[*] Loading dataset from '{resolved_input}'...")
    try:
        df = pd.read_csv(resolved_input, low_memory=False)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please run Practical 3 first.")
        sys.exit(1)
        
    print(f"[+] Total Rows Loaded to Label: {len(df):,}")
    
    # Ensure text columns are string type
    df['resource_requested'] = df['resource_requested'].fillna('').astype(str)
    df['user_agent'] = df['user_agent'].fillna('').astype(str)
    
    # Combine relevant text fields into a single search target
    combined_text = df['resource_requested'] + " " + df['user_agent']
    
    # 2. Define security attack patterns
    sqli_pattern = r"(?:'|\%27)|(?:\-\-)|(?:\bOR\b.*=.*)|(?:\bUNION\b.*SELECT\b)|(?:\bDROP\b.*TABLE\b)"
    path_traversal_pattern = r"(?:\.\./|\.\.\\|/etc/passwd|boot\.ini)"
    # Shared rule with the backend upload parser: label and bot_family never disagree.
    bot_scanner_pattern = BOT_LABEL_PATTERN
    
    # 3. Apply classification rules across combined text fields
    print("\n[*] Applying security rules across resource and user-agent fields...")
    
    is_sqli = combined_text.str.contains(sqli_pattern, regex=True, case=False)
    is_path_traversal = combined_text.str.contains(path_traversal_pattern, regex=True, case=False)
    is_brute_force = df['user_agent'].str.contains(bot_scanner_pattern, regex=True, case=False)
    
    # Assign labels based on priority
    df['label'] = 'benign'
    df.loc[is_brute_force, 'label'] = 'brute_force'
    df.loc[is_path_traversal, 'label'] = 'path_traversal'
    df.loc[is_sqli, 'label'] = 'sqli'

    # 3b. Bot sub-classification: WHICH tool? (shared taxonomy; metadata only,
    # `label` stays the ML target so Practicals 6-9 are unaffected)
    print("\n[*] Sub-classifying brute-force traffic by attacking tool...")
    df['bot_family'] = df['user_agent'].astype(str).map(classify_bot)
    needs_fallback = is_brute_force & df['bot_family'].isin(['browser', 'unknown'])
    df.loc[needs_fallback, 'bot_family'] = 'other_bot'

    # 3c. SQLi payload-variant sub-classification: WHICH technique? (shared
    # taxonomy; metadata only, `label` stays the ML target)
    print("\n[*] Sub-classifying SQLi traffic by payload variant...")
    df['sqli_variant'] = '-'
    is_sqli = df['label'] == 'sqli'
    df.loc[is_sqli, 'sqli_variant'] = df.loc[is_sqli, 'resource_requested'].astype(str).map(classify_sqli)

    # 4. Print Label Distribution Summary
    print("\n--- LABEL DISTRIBUTION SUMMARY ---")
    label_counts = df['label'].value_counts()
    summary_data = []
    for label_name, count in label_counts.items():
        percentage = (count / len(df)) * 100
        summary_data.append([label_name.upper(), f"{count:,}", f"{percentage:.2f}%"])
    print(tabulate(summary_data, headers=["Label Category", "Record Count", "Percentage"], tablefmt="fancy_grid"))

    # 4b. Print Bot/Tool Distribution Summary (sub-classification)
    print("\n--- BOT / TOOL DISTRIBUTION SUMMARY (which bot?) ---")
    fam_counts = df['bot_family'].value_counts()
    tool_data = []
    for fam, count in fam_counts.items():
        percentage = (count / len(df)) * 100
        tool_data.append([family_label(str(fam)), f"{count:,}", f"{percentage:.2f}%"])
    print(tabulate(tool_data, headers=["Attacking Tool", "Record Count", "Percentage"], tablefmt="fancy_grid"))

    # 4c. Print SQLi Variant Distribution Summary (sub-classification)
    print("\n--- SQLI PAYLOAD VARIANT SUMMARY (which technique?) ---")
    var_counts = df[df['sqli_variant'] != '-']['sqli_variant'].value_counts()
    variant_data = []
    for var, count in var_counts.items():
        percentage = (count / len(df)) * 100
        variant_data.append([variant_label(str(var)), f"{count:,}", f"{percentage:.2f}%"])
    if variant_data:
        print(tabulate(variant_data, headers=["Payload Variant", "Record Count", "Percentage"], tablefmt="fancy_grid"))
    else:
        print("(no SQLi rows in this dataset)")
    
    # 5. Save labeled dataset
    df.to_csv(resolved_output, index=False)
    print(f"\n[+] Saved labeled dataset to '{resolved_output}'!")
    
    # 6. Export plot
    plots_dir = os.path.join(BASE_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    plt.style.use('seaborn-v0_8')
    
    print("\n[*] Exporting and showing plot_p4_label_distribution.png...")
    plt.figure(figsize=(10, 6))
    sns.barplot(x=label_counts.index, y=label_counts.values, palette='magma', hue=label_counts.index, legend=False)
    plt.title("Distribution of Security Classification Labels", fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("Assigned Label", fontsize=12)
    plt.ylabel("Number of Logs", fontsize=12)
    plt.yscale('log') # Log scale to make rare attack classes clearly visible
    
    for i, val in enumerate(label_counts.values):
        plt.text(i, val * 1.1, f"{val:,}", ha='center', va='bottom', fontweight='bold')
        
    plt.tight_layout()
    plt.savefig(os.path.join(plots_dir, "plot_p4_label_distribution.png"), dpi=300)
    
    is_interactive = sys.stdin.isatty() and '--headless' not in sys.argv
    if is_interactive:
        try:
            print("    -> Close the plot window to continue...")
            plt.show()
        except Exception:
            pass
    plt.close()
    print("=" * 60)

if __name__ == "__main__":
    label_log_requests("cleaned_logs.csv", "labeled_logs.csv")
