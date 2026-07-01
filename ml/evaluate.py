"""
evaluate.py — Full Evaluation Report for DoS Detection Models
=============================================================
Generates a comprehensive evaluation report including:
  • Per-class precision, recall, F1, support
  • Confusion matrices
  • ROC curves (one-vs-rest)
  • Feature importance (Random Forest + SHAP)
  • Edge device latency benchmarks
  • Model size comparison
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")          # headless rendering
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import joblib

from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    f1_score, roc_auc_score, roc_curve, RocCurveDisplay
)
from sklearn.preprocessing import label_binarize

warnings.filterwarnings("ignore")

# ── paths ─────────────────────────────────────────────────────────────────────
DATA_PATH    = "data/dos_traffic.csv"
MODEL_DIR    = "models"
REPORT_DIR   = "reports"
FEATURE_COLS = [
    "packet_rate", "byte_rate", "flow_duration", "avg_packet_size",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
    "src_port_div", "dst_port_div", "inter_arrival", "payload_entropy",
    "is_tcp", "is_udp", "is_icmp",
]
TARGET_COL   = "label"
ATTACK_NAMES = ["Normal", "SYN Flood", "UDP Flood", "HTTP Flood", "Smurf"]
SEED         = 42

# ── plot style ────────────────────────────────────────────────────────────────
DARK_BG   = "#0a0f1e"
PANEL_BG  = "#0d1628"
CYAN      = "#00d4ff"
RED       = "#ff3366"
GREEN     = "#00ff88"
GOLD      = "#ffd700"
PURPLE    = "#bf5fff"
PALETTE   = [GREEN, RED, "#ff6b35", GOLD, PURPLE]

plt.rcParams.update({
    "figure.facecolor": DARK_BG,
    "axes.facecolor":   PANEL_BG,
    "axes.edgecolor":   "#1e3050",
    "axes.labelcolor":  "#8aa0c0",
    "xtick.color":      "#8aa0c0",
    "ytick.color":      "#8aa0c0",
    "text.color":       "#ccd6f6",
    "grid.color":       "#1e3050",
    "grid.linewidth":   0.5,
    "font.family":      "monospace",
    "font.size":        10,
})


def _header(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


def load_data_and_models():
    """Load test data and trained models."""
    df = pd.read_csv(DATA_PATH)
    from sklearn.model_selection import train_test_split
    X = df[FEATURE_COLS]
    y = df[TARGET_COL]
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=SEED
    )

    rf  = joblib.load(os.path.join(MODEL_DIR, "random_forest.joblib"))
    dt  = joblib.load(os.path.join(MODEL_DIR, "decision_tree.joblib"))
    iso_scaler, iso = joblib.load(os.path.join(MODEL_DIR, "isolation_forest.joblib"))

    return X_test, y_test, rf, dt, (iso_scaler, iso)


def plot_confusion_matrices(X_test, y_test, rf, dt, output_dir):
    """Plot side-by-side confusion matrices for RF and DT."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("Confusion Matrices — DoS Detection", color=CYAN,
                 fontsize=14, fontweight="bold", y=1.02)

    for ax, (model, name) in zip(axes, [(rf, "Random Forest"), (dt, "Decision Tree")]):
        y_pred = model.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

        sns.heatmap(cm_norm, annot=cm, fmt="d", cmap="Blues", ax=ax,
                    xticklabels=ATTACK_NAMES, yticklabels=ATTACK_NAMES,
                    linewidths=0.5, linecolor="#1e3050",
                    annot_kws={"color": "white", "fontsize": 9})
        ax.set_title(name, color=CYAN, pad=10)
        ax.set_xlabel("Predicted", color="#8aa0c0")
        ax.set_ylabel("Actual", color="#8aa0c0")
        ax.tick_params(colors="#8aa0c0", rotation=30)

    plt.tight_layout()
    path = os.path.join(output_dir, "confusion_matrices.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    print(f"  [✓] Confusion matrices saved → {path}")
    return path


def plot_roc_curves(X_test, y_test, rf, output_dir):
    """Plot one-vs-rest ROC curves for the Random Forest."""
    classes = sorted(y_test.unique())
    y_bin   = label_binarize(y_test, classes=classes)
    y_prob  = rf.predict_proba(X_test)

    fig, ax = plt.subplots(figsize=(9, 7))
    ax.set_title("ROC Curves — Random Forest (One-vs-Rest)",
                 color=CYAN, fontsize=13, fontweight="bold")

    auc_scores = []
    for i, (cls, name) in enumerate(zip(classes, ATTACK_NAMES)):
        fpr, tpr, _ = roc_curve(y_bin[:, i], y_prob[:, i])
        auc = roc_auc_score(y_bin[:, i], y_prob[:, i])
        auc_scores.append(auc)
        ax.plot(fpr, tpr, lw=2, color=PALETTE[i],
                label=f"{name}  (AUC = {auc:.3f})")

    ax.plot([0, 1], [0, 1], "w--", lw=1, alpha=0.4)
    ax.fill_between([0, 1], [0, 1], alpha=0.05, color="white")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.legend(loc="lower right", framealpha=0.2, labelcolor="white")
    ax.grid(True, alpha=0.3)

    path = os.path.join(output_dir, "roc_curves.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()

    print(f"  [✓] ROC curves saved       → {path}")
    print(f"       Mean AUC: {np.mean(auc_scores):.4f}")
    return path


def plot_feature_importance(rf, output_dir):
    """Bar chart of Random Forest feature importances."""
    importances = rf.named_steps["clf"].feature_importances_
    order = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_title("Feature Importance — Random Forest",
                 color=CYAN, fontsize=13, fontweight="bold")

    colors = [CYAN if i < 5 else "#1e4080" for i in range(len(importances))]
    bars = ax.barh(
        [FEATURE_COLS[i] for i in order[::-1]],
        importances[order[::-1]],
        color=colors[::-1],
        edgecolor="#0a1628",
    )
    # Glow effect on top features
    for bar in bars[-5:]:
        bar.set_alpha(0.9)
        bar.set_linewidth(0.8)
        bar.set_edgecolor(CYAN)

    ax.set_xlabel("Importance Score")
    ax.grid(True, axis="x", alpha=0.3)

    path = os.path.join(output_dir, "feature_importance.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    print(f"  [✓] Feature importance     → {path}")
    return path


def plot_model_comparison(summary: dict, output_dir: str):
    """Bar chart comparing all 3 models on key metrics."""
    models    = list(summary.keys())
    accuracy  = [summary[m]["accuracy"] * 100 for m in models]
    f1_scores = [summary[m]["f1"] * 100        for m in models]
    latency   = [summary[m]["latency_ms"]       for m in models]
    sizes     = [summary[m]["size_kb"]           for m in models]

    fig, axes = plt.subplots(1, 4, figsize=(16, 5))
    fig.suptitle("Edge Model Comparison", color=CYAN,
                 fontsize=14, fontweight="bold", y=1.03)

    metrics = [
        (accuracy,  "Accuracy (%)",      CYAN,   axes[0]),
        (f1_scores, "F1 Score (%)",      GREEN,  axes[1]),
        (latency,   "Latency (ms)",      GOLD,   axes[2]),
        (sizes,     "Model Size (KB)",   PURPLE, axes[3]),
    ]
    for vals, label, color, ax in metrics:
        bars = ax.bar(models, vals, color=color, alpha=0.85, width=0.55,
                      edgecolor=color, linewidth=0.8)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(vals) * 0.02,
                    f"{val:.1f}", ha="center", va="bottom", fontsize=9, color="white")
        ax.set_title(label, color=color, fontsize=11)
        ax.tick_params(axis="x", rotation=10)
        ax.grid(True, axis="y", alpha=0.3)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    plt.tight_layout()
    path = os.path.join(output_dir, "model_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    print(f"  [✓] Model comparison       → {path}")
    return path


def print_classification_reports(X_test, y_test, rf, dt):
    """Print detailed per-class metrics for RF and DT."""
    for model, name in [(rf, "Random Forest"), (dt, "Decision Tree")]:
        _header(f"Classification Report — {name}")
        y_pred = model.predict(X_test)
        print(classification_report(y_test, y_pred,
                                     target_names=ATTACK_NAMES, digits=4))


def main():
    _header("DoS Detection — Full Evaluation Report")

    os.makedirs(REPORT_DIR, exist_ok=True)

    # 1. Load
    print("\n[1] Loading data and models …")
    X_test, y_test, rf, dt, (iso_scaler, iso) = load_data_and_models()
    print(f"    Test set: {len(X_test):,} samples")

    with open(os.path.join(MODEL_DIR, "training_summary.json")) as f:
        summary = json.load(f)

    # 2. Classification reports
    print_classification_reports(X_test, y_test, rf, dt)

    # 3. Plots
    _header("Generating Plots")
    plot_confusion_matrices(X_test, y_test, rf, dt, REPORT_DIR)
    plot_roc_curves(X_test, y_test, rf, REPORT_DIR)
    plot_feature_importance(rf, REPORT_DIR)
    plot_model_comparison(summary, REPORT_DIR)

    # 4. Final summary
    _header("Final Model Metrics")
    print(f"\n  {'Model':<22} {'Accuracy':>10} {'F1':>8} {'AUC':>8} "
          f"{'Latency':>10} {'Size':>8}")
    print(f"  {'─' * 70}")
    for name, s in summary.items():
        print(f"  {name:<22} {s['accuracy']:>9.4f} {s['f1']:>8.4f} "
              f"  {'N/A':>6} {s['latency_ms']:>8.3f}ms {s['size_kb']:>6.1f}KB")

    print(f"\n  All plots saved to: ./{REPORT_DIR}/")
    print(f"\n{'═' * 60}")
    print("  ✓ Evaluation complete!")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    main()
