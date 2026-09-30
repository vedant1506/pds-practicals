import os
import sys
import pandas as pd
import numpy as np
import matplotlib
if 'DISPLAY' not in os.environ or '--headless' in sys.argv:
    matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate
from sklearn.model_selection import train_test_split
from path_utils import resolve_input_file, resolve_export_file, BASE_DIR

def balance_and_split(input_file="engineered_features.csv", train_output="train_dataset.csv", test_output="test_dataset.csv"):
    print("=" * 60)
    print("PRACTICAL 6: Dataset Splitting & Balancing (SMOTE)")
    print("=" * 60)

    resolved_input = resolve_input_file(input_file)
    resolved_train_out = resolve_export_file(train_output)
    resolved_test_out = resolve_export_file(test_output)

    # 1. Load the features dataset
    print(f"[*] Loading dataset from '{resolved_input}'...")
    try:
        df = pd.read_csv(resolved_input, low_memory=False)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please run Practical 5 first.")
        sys.exit(1)

    print(f"[+] Total Records Loaded: {len(df):,}")

    # Define features and target
    feature_cols = ['ip_request_count', 'time_diff_seconds', 'status_code_404_count', 'is_bot_agent', 'url_entropy']
    
    # Clean any NaN values just in case
    df = df.dropna(subset=feature_cols + ['label']).reset_index(drop=True)
    
    X = df[feature_cols]
    y = df['label']

    # 2. Train-Test Split (80% Train, 20% Test, Stratified)
    print("\n[*] Performing 80/20 Stratified Train-Test Split...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n--- Original Training Set Label Distribution ---")
    orig_dist = y_train.value_counts()
    orig_pct = y_train.value_counts(normalize=True) * 100
    orig_summary = []
    for label in orig_dist.index:
        orig_summary.append([label.upper(), f"{orig_dist[label]:,}", f"{orig_pct[label]:.4f}%"])
    print(tabulate(orig_summary, headers=["Class", "Count", "Percentage"], tablefmt="fancy_grid"))

    # 3. Handle Class Imbalance
    # To prevent memory exhaust/extremely long wait times on ~1.6M training records, 
    # we first cap the maximum class size of majority classes to 50,000 via random undersampling,
    # and then apply SMOTE to oversample minority classes up to that cap.
    target_cap = 50000
    
    X_train_bal, y_train_bal = None, None
    
    try:
        from imblearn.over_sampling import SMOTE
        print(f"\n[+] 'imblearn' package detected. Applying hybrid Undersampling + SMOTE...")
        
        # Step A: Undersample majority classes down to the target_cap
        train_temp = X_train.copy()
        train_temp['label'] = y_train
        
        sampled_dfs = []
        for cls_name in train_temp['label'].unique():
            cls_df = train_temp[train_temp['label'] == cls_name]
            if len(cls_df) > target_cap:
                print(f"  • Downsampling majority class '{cls_name}' to {target_cap:,}...")
                sampled_dfs.append(cls_df.sample(n=target_cap, random_state=42))
            else:
                sampled_dfs.append(cls_df)
                
        downsampled_train = pd.concat(sampled_dfs).reset_index(drop=True)
        X_train_ds = downsampled_train[feature_cols]
        y_train_ds = downsampled_train['label']
        
        # Step B: Oversample minority classes using SMOTE to match the target_cap
        print(f"  • Applying SMOTE to oversample minority classes to {target_cap:,}...")
        smote = SMOTE(random_state=42)
        X_train_bal, y_train_bal = smote.fit_resample(X_train_ds, y_train_ds)
        
    except ImportError:
        print("\n⚠️ 'imblearn' not installed. Falling back to Random Undersampling of majority class...")
        train_temp = X_train.copy()
        train_temp['label'] = y_train
        min_class_size = train_temp['label'].value_counts().min()
        
        balanced_dfs = []
        for cls_name in train_temp['label'].unique():
            cls_df = train_temp[train_temp['label'] == cls_name]
            balanced_dfs.append(cls_df.sample(n=min_class_size, random_state=42))
            
        balanced_train = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
        X_train_bal = balanced_train[feature_cols]
        y_train_bal = balanced_train['label']

    print("\n--- Balanced Training Set Label Distribution ---")
    bal_dist = y_train_bal.value_counts()
    bal_pct = y_train_bal.value_counts(normalize=True) * 100
    bal_summary = []
    for label in bal_dist.index:
        bal_summary.append([label.upper(), f"{bal_dist[label]:,}", f"{bal_pct[label]:.2f}%"])
    print(tabulate(bal_summary, headers=["Class", "Count", "Percentage"], tablefmt="fancy_grid"))

    # 4. Save Training and Testing Sets to CSV
    print(f"\n[*] Saving datasets...")
    train_df_out = X_train_bal.copy()
    train_df_out['label'] = y_train_bal
    train_df_out.to_csv(resolved_train_out, index=False)
    
    test_df_out = X_test.copy()
    test_df_out['label'] = y_test
    test_df_out.to_csv(resolved_test_out, index=False)
    
    print(f"[+] Saved balanced training set to '{resolved_train_out}'!")
    print(f"[+] Saved testing set to '{resolved_test_out}'!")

    # 5. Export Plots
    plots_dir = os.path.join(BASE_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    plt.style.use('seaborn-v0_8')
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    
    display_labels = ['Brute Force', 'Benign', 'SQLi', 'Path Traversal']
    order_labels = y_train.value_counts().index
    
    # Before balancing
    sns.countplot(x=y_train, ax=axes[0], order=order_labels, hue=y_train, palette="viridis", legend=False)
    axes[0].set_title("Before Balancing\n(Original Train Set)", fontsize=13, fontweight='bold', pad=12)
    axes[0].set_yscale('log')
    axes[0].set_ylabel("Count (Log Scale)", fontsize=11)
    axes[0].set_xlabel("Class Label", fontsize=11)
    axes[0].set_xticks(range(len(display_labels)))
    axes[0].set_xticklabels(display_labels, rotation=25, ha='right')
    
    for p in axes[0].patches:
        height = p.get_height()
        if height > 0:
            axes[0].annotate(f'{int(height):,}',
                            (p.get_x() + p.get_width() / 2., height * 1.25),
                            ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # After balancing
    order_bal_labels = y_train_bal.value_counts().index
    sns.countplot(x=y_train_bal, ax=axes[1], order=order_bal_labels, hue=y_train_bal, palette="viridis", legend=False)
    axes[1].set_title("After Balancing\n(SMOTE / Resampled Train Set)", fontsize=13, fontweight='bold', pad=12)
    axes[1].set_ylabel("Count", fontsize=11)
    axes[1].set_xlabel("Class Label", fontsize=11)
    axes[1].set_xticks(range(len(display_labels)))
    axes[1].set_xticklabels(display_labels, rotation=25, ha='right')
    
    for p in axes[1].patches:
        height = p.get_height()
        if height > 0:
            axes[1].annotate(f'{int(height):,}',
                            (p.get_x() + p.get_width() / 2., height * 1.02),
                            ha='center', va='bottom', fontsize=9, fontweight='bold')

    axes[0].set_ylim(top=axes[0].get_ylim()[1] * 4)
    axes[1].set_ylim(top=axes[1].get_ylim()[1] * 1.12)

    plt.tight_layout(pad=2.5)
    plot_path = os.path.join(plots_dir, "plot_p6_class_distribution.png")
    plt.savefig(plot_path, dpi=300)
    print(f"[+] Exported and saved distribution plot to '{plot_path}'!")

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
    balance_and_split()
