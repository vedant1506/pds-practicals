import os
import sys
import time
import pandas as pd
import numpy as np
import matplotlib
if 'DISPLAY' not in os.environ or '--headless' in sys.argv:
    matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from tabulate import tabulate

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

import xgboost as xgb
import lightgbm as lgb


def run_advanced_ml_benchmark(train_file="train_dataset.csv", test_file="test_dataset.csv"):
    print("=" * 70)
    print("ADVANCED ML BENCHMARK: Gradient Boosting & Neural Network Attack Detection")
    print("=" * 70)

    # 1. Load Datasets
    print(f"[*] Loading training dataset from '{train_file}'...")
    if not os.path.exists(train_file):
        print(f"Error: '{train_file}' not found. Run Practical 6 first.")
        sys.exit(1)
    train_df = pd.read_csv(train_file)

    print(f"[*] Loading testing dataset from '{test_file}'...")
    if not os.path.exists(test_file):
        print(f"Error: '{test_file}' not found. Run Practical 6 first.")
        sys.exit(1)
    test_df = pd.read_csv(test_file)

    feature_cols = ['ip_request_count', 'time_diff_seconds', 'status_code_404_count', 'is_bot_agent', 'url_entropy']
    target_col = 'label'

    train_df = train_df.dropna(subset=feature_cols + [target_col]).reset_index(drop=True)
    test_df = test_df.dropna(subset=feature_cols + [target_col]).reset_index(drop=True)

    X_train, y_train_raw = train_df[feature_cols], train_df[target_col]
    X_test, y_test_raw = test_df[feature_cols], test_df[target_col]

    # Encode String Labels into Numeric Integers for XGBoost/LightGBM compatibility
    le = LabelEncoder()
    y_train = le.fit_transform(y_train_raw)
    y_test = le.transform(y_test_raw)

    labels_order = list(range(len(le.classes_)))
    display_labels = [c.upper() for c in le.classes_]

    print(f"[+] Balanced Training Samples: {len(X_train):,}")
    print(f"[+] Evaluation Testing Samples: {len(X_test):,}")

    # Standardize Features for scaling-sensitive models
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Model Evaluation Storage
    models_dict = {}
    benchmark_results = []
    confusion_matrices = {}

    # Define Model Configurations
    models_to_run = {
        "Logistic Regression": {
            "model": LogisticRegression(max_iter=1000, random_state=42),
            "use_scaled": True
        },
        "Random Forest": {
            "model": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
            "use_scaled": False
        },
        "XGBoost": {
            "model": xgb.XGBClassifier(n_estimators=100, max_depth=8, learning_rate=0.1,
                                       objective='multi:softprob', random_state=42, n_jobs=-1),
            "use_scaled": False
        },
        "LightGBM": {
            "model": lgb.LGBMClassifier(n_estimators=100, max_depth=8, learning_rate=0.1,
                                        random_state=42, n_jobs=-1, verbose=-1),
            "use_scaled": False
        },
        "Neural Network (MLP)": {
            "model": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=50, batch_size=2048,
                                   activation='relu', solver='adam', random_state=42, early_stopping=True),
            "use_scaled": True
        }
    }

    # -------------------------------------------------------------
    # Model Training & Benchmarking Loop
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("TRAINING & INFERENCE BENCHMARK EVALUATION")
    print("=" * 70)

    for name, config in models_to_run.items():
        print(f"\n[*] Training Model: {name}...")
        model = config["model"]
        use_scaled = config["use_scaled"]

        X_tr = X_train_scaled if use_scaled else X_train
        X_te = X_test_scaled if use_scaled else X_test

        # Measure Training Time
        t_start_train = time.time()
        model.fit(X_tr, y_train)
        t_train = time.time() - t_start_train

        # Measure Inference Speed on Test Set
        t_start_infer = time.time()
        y_pred = model.predict(X_te)
        t_infer = time.time() - t_start_infer

        # Compute Metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        # Compute Minority-Class Recalls (SQLI & PATH_TRAVERSAL)
        sqli_idx = list(le.classes_).index('sqli') if 'sqli' in le.classes_ else -1
        pt_idx = list(le.classes_).index('path_traversal') if 'path_traversal' in le.classes_ else -1

        cm = confusion_matrix(y_test, y_pred, labels=labels_order)
        confusion_matrices[name] = cm

        sqli_rec = (cm[sqli_idx, sqli_idx] / cm[sqli_idx].sum()) * 100 if sqli_idx != -1 and cm[sqli_idx].sum() > 0 else 0
        pt_rec = (cm[pt_idx, pt_idx] / cm[pt_idx].sum()) * 100 if pt_idx != -1 and cm[pt_idx].sum() > 0 else 0

        infer_speed_per_10k = (t_infer / len(X_test)) * 10000 * 1000  # ms per 10k predictions

        benchmark_results.append({
            'Model': name,
            'Accuracy': acc * 100,
            'Precision': prec * 100,
            'Recall': rec * 100,
            'F1-Score': f1 * 100,
            'SQLi Recall': sqli_rec,
            'Path Traversal Recall': pt_rec,
            'Train Time (s)': t_train,
            'Infer Time / 10k (ms)': infer_speed_per_10k
        })

        models_dict[name] = model

        print(f"    [+] {name} Training Finished in {t_train:.2f}s | Accuracy: {acc*100:.2f}% | F1: {f1*100:.2f}%")
        print(f"    [+] Minority Recalls -> SQLi: {sqli_rec:.2f}% | Path Traversal: {pt_rec:.2f}%")

    # Convert Benchmark Results to DataFrame
    results_df = pd.DataFrame(benchmark_results)

    print("\n" + "=" * 70)
    print("SUMMARY COMPARISON TABLE: ALL ALGORITHMS")
    print("=" * 70)
    summary_headers = ["Model Name", "Accuracy", "Precision", "Recall", "F1-Score", "SQLi Recall", "Path Trav. Recall", "Train Time (s)", "Infer/10k (ms)"]
    summary_rows = []
    for _, r in results_df.iterrows():
        summary_rows.append([
            r['Model'],
            f"{r['Accuracy']:.2f}%",
            f"{r['Precision']:.2f}%",
            f"{r['Recall']:.2f}%",
            f"{r['F1-Score']:.2f}%",
            f"{r['SQLi Recall']:.2f}%",
            f"{r['Path Traversal Recall']:.2f}%",
            f"{r['Train Time (s)']:.2f}s",
            f"{r['Infer Time / 10k (ms)']:.1f}ms"
        ])
    print(tabulate(summary_rows, headers=summary_headers, tablefmt="fancy_grid"))

    # -------------------------------------------------------------
    # Export Visualization Artifacts
    # -------------------------------------------------------------
    os.makedirs("./plots", exist_ok=True)
    plt.style.use('seaborn-v0_8')
    is_interactive = sys.stdin.isatty() and '--headless' not in sys.argv

    # Plot 1: Grid of Confusion Matrices for All 5 Models
    print("\n[*] Exporting plot_advanced_ml_confusion_matrices.png...")
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    axes = axes.flatten()

    for idx, (name, cm) in enumerate(confusion_matrices.items()):
        ax = axes[idx]
        sns.heatmap(cm, annot=True, fmt=',d', cmap='Blues', ax=ax,
                    xticklabels=display_labels, yticklabels=display_labels)
        ax.set_title(f"{name}\nAccuracy: {results_df.loc[results_df['Model']==name, 'Accuracy'].values[0]:.2f}%",
                     fontsize=11, fontweight='bold', pad=10)
        ax.set_xlabel("Predicted Label", fontsize=10)
        ax.set_ylabel("True Label", fontsize=10)
        ax.tick_params(axis='y', rotation=0)
        ax.set_xticklabels(display_labels, rotation=25, ha='right')

    # Remove the 6th unused subplot in 2x3 grid
    fig.delaxes(axes[5])
    plt.tight_layout(pad=2.5)
    plot1_path = "./plots/plot_advanced_ml_confusion_matrices.png"
    plt.savefig(plot1_path, dpi=300)
    print(f"    [+] Saved to '{plot1_path}'!")
    if is_interactive:
        try:
            plt.show()
        except Exception:
            pass
    plt.close()

    # Plot 2: Overall Metrics Comparison Bar Chart
    print("[*] Exporting plot_advanced_ml_metric_comparison.png...")
    metrics_melted = pd.melt(results_df, id_vars=['Model'], value_vars=['Accuracy', 'Precision', 'Recall', 'F1-Score'],
                             var_name='Metric', value_name='Score (%)')

    plt.figure(figsize=(12, 6))
    sns.barplot(data=metrics_melted, x='Metric', y='Score (%)', hue='Model', palette='Set2')
    plt.title("Algorithm Comparison across Overall Classification Metrics", fontsize=13, fontweight='bold', pad=15)
    plt.xlabel("Evaluation Metric", fontsize=11)
    plt.ylabel("Performance Score (%)", fontsize=11)
    plt.ylim(0, 115)
    plt.legend(title="Algorithm", fontsize=10)

    for p in plt.gca().patches:
        height = p.get_height()
        if height > 0:
            plt.gca().annotate(f"{height:.1f}%",
                                (p.get_x() + p.get_width() / 2., height + 1.2),
                                ha='center', va='bottom', fontsize=8, fontweight='bold')

    plt.tight_layout()
    plot2_path = "./plots/plot_advanced_ml_metric_comparison.png"
    plt.savefig(plot2_path, dpi=300)
    print(f"    [+] Saved to '{plot2_path}'!")
    if is_interactive:
        try:
            plt.show()
        except Exception:
            pass
    plt.close()

    # Plot 3: Minority Class Detection Sensitivity (SQLi & Path Traversal Recall)
    print("[*] Exporting plot_advanced_ml_minority_recall.png...")
    minority_melted = pd.melt(results_df, id_vars=['Model'], value_vars=['SQLi Recall', 'Path Traversal Recall'],
                              var_name='Attack Category', value_name='Recall Sensitivity (%)')

    plt.figure(figsize=(10, 6))
    sns.barplot(data=minority_melted, x='Attack Category', y='Recall Sensitivity (%)', hue='Model', palette='magma')
    plt.title("Minority Class Detection Sensitivity (SQLi vs Path Traversal Recall)", fontsize=13, fontweight='bold', pad=15)
    plt.xlabel("Rare Attack Type", fontsize=11)
    plt.ylabel("True Positive Recall Rate (%)", fontsize=11)
    plt.ylim(0, 115)
    plt.legend(title="Algorithm", fontsize=10)

    for p in plt.gca().patches:
        height = p.get_height()
        if height > 0:
            plt.gca().annotate(f"{height:.1f}%",
                                (p.get_x() + p.get_width() / 2., height + 1.2),
                                ha='center', va='bottom', fontsize=8, fontweight='bold')

    plt.tight_layout()
    plot3_path = "./plots/plot_advanced_ml_minority_recall.png"
    plt.savefig(plot3_path, dpi=300)
    print(f"    [+] Saved to '{plot3_path}'!")
    if is_interactive:
        try:
            plt.show()
        except Exception:
            pass
    plt.close()

    # Plot 4: Inference Latency Benchmark Bar Chart
    print("[*] Exporting plot_advanced_ml_latency_benchmark.png...")
    plt.figure(figsize=(10, 6))
    sns.barplot(data=results_df, x='Infer Time / 10k (ms)', y='Model', hue='Model', palette='viridis', legend=False)
    plt.title("Inference Latency Benchmark (Milliseconds per 10,000 Predictions)", fontsize=13, fontweight='bold', pad=15)
    plt.xlabel("Latency (ms per 10,000 records)", fontsize=11)
    plt.ylabel("Algorithm", fontsize=11)

    for i, val in enumerate(results_df['Infer Time / 10k (ms)']):
        plt.text(val + 1.0, i, f"{val:.1f} ms", va='center', fontweight='bold', fontsize=10)

    plt.tight_layout()
    plot4_path = "./plots/plot_advanced_ml_latency_benchmark.png"
    plt.savefig(plot4_path, dpi=300)
    print(f"    [+] Saved to '{plot4_path}'!")
    if is_interactive:
        try:
            plt.show()
        except Exception:
            pass
    plt.close()

    print("\n[+] Advanced Machine Learning Benchmark successfully completed!")
    print("=" * 70)


if __name__ == "__main__":
    run_advanced_ml_benchmark()
