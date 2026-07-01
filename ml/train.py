"""
train.py — Edge ML Model Training for DoS Attack Detection
===========================================================
Trains three classifiers optimized for edge deployment:

  1. Random Forest  — primary model, high accuracy, fast inference
  2. Decision Tree  — ultra-lightweight fallback (<3KB)
  3. Isolation Forest — unsupervised anomaly detector (no labels needed)

Follows strict ML best practices:
  • Train/test split BEFORE any preprocessing
  • Pipeline-based to prevent data leakage
  • Class imbalance handled with class_weight='balanced'
  • 5-fold stratified cross-validation for reliable estimates
"""

import os
import sys
import json
import time
import warnings
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, f1_score

warnings.filterwarnings("ignore")

# ── paths ─────────────────────────────────────────────────────────────────────
DATA_PATH   = "data/dos_traffic.csv"
MODEL_DIR   = "models"
FEATURE_COLS = [
    "packet_rate", "byte_rate", "flow_duration", "avg_packet_size",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
    "src_port_div", "dst_port_div", "inter_arrival", "payload_entropy",
    "is_tcp", "is_udp", "is_icmp",
]
TARGET_COL   = "label"
ATTACK_NAMES = {0: "Normal", 1: "SYN Flood", 2: "UDP Flood",
                3: "HTTP Flood", 4: "Smurf"}
SEED = 42


def _header(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


def load_or_generate_data() -> pd.DataFrame:
    """Load dataset, generating it first if needed."""
    if not os.path.exists(DATA_PATH):
        print("[!] Dataset not found — running data_generator.py …")
        from data_generator import generate_dataset
        generate_dataset(output_path=DATA_PATH)
    return pd.read_csv(DATA_PATH)


def train_random_forest(X_train, y_train, X_test, y_test):
    """Primary edge model: Random Forest with standard scaling."""
    _header("1 / 3  Random Forest (Primary Model)")

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_leaf=5,
            class_weight="balanced",
            n_jobs=-1,
            random_state=SEED,
        )),
    ])

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    cv_scores = cross_val_score(pipe, X_train, y_train, cv=cv,
                                scoring="f1_weighted", n_jobs=-1)
    print(f"  CV F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    t0 = time.perf_counter()
    pipe.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average="weighted")

    print(f"  Test Accuracy : {acc:.4f}")
    print(f"  Test F1       : {f1:.4f}")
    print(f"  Train time    : {train_time:.2f}s")

    # Measure inference latency
    single = X_test.iloc[[0]]
    times = []
    for _ in range(1000):
        t = time.perf_counter()
        pipe.predict(single)
        times.append((time.perf_counter() - t) * 1000)
    latency_ms = np.median(times)
    print(f"  Infer latency : {latency_ms:.3f} ms/sample (median, 1000 runs)")

    # Feature importances
    importances = pipe.named_steps["clf"].feature_importances_
    feat_imp = dict(zip(FEATURE_COLS, importances.tolist()))

    # Save
    path = os.path.join(MODEL_DIR, "random_forest.joblib")
    joblib.dump(pipe, path)
    print(f"  Saved → {path}")

    return {
        "model": pipe,
        "accuracy": float(acc),
        "f1": float(f1),
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "latency_ms": float(latency_ms),
        "train_time_s": float(train_time),
        "feature_importances": feat_imp,
        "model_path": path,
    }


def train_decision_tree(X_train, y_train, X_test, y_test):
    """Ultra-lightweight edge model: Decision Tree (max_depth=5, ~2KB)."""
    _header("2 / 3  Decision Tree (Lightweight Edge Model)")

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    DecisionTreeClassifier(
            max_depth=5,
            min_samples_leaf=10,
            class_weight="balanced",
            random_state=SEED,
        )),
    ])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    cv_scores = cross_val_score(pipe, X_train, y_train, cv=cv,
                                scoring="f1_weighted", n_jobs=-1)
    print(f"  CV F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    t0 = time.perf_counter()
    pipe.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average="weighted")

    print(f"  Test Accuracy : {acc:.4f}")
    print(f"  Test F1       : {f1:.4f}")
    print(f"  Train time    : {train_time:.3f}s")

    # Latency
    single = X_test.iloc[[0]]
    times = [None] * 1000
    for i in range(1000):
        t = time.perf_counter()
        pipe.predict(single)
        times[i] = (time.perf_counter() - t) * 1000
    latency_ms = np.median(times)
    print(f"  Infer latency : {latency_ms:.3f} ms/sample (median, 1000 runs)")

    # Export rules as text
    scaler = pipe.named_steps["scaler"]
    tree_rules = export_text(pipe.named_steps["clf"],
                             feature_names=FEATURE_COLS,
                             max_depth=5)
    rules_path = os.path.join(MODEL_DIR, "decision_tree_rules.txt")
    with open(rules_path, "w") as f:
        f.write(tree_rules)
    print(f"  Rules saved   → {rules_path}")

    # Export thresholds as JSON for JavaScript edge inference
    clf = pipe.named_steps["clf"]
    tree_json = {
        "feature_names": FEATURE_COLS,
        "class_names": [ATTACK_NAMES[i] for i in range(5)],
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "children_left": clf.tree_.children_left.tolist(),
        "children_right": clf.tree_.children_right.tolist(),
        "feature": clf.tree_.feature.tolist(),
        "threshold": clf.tree_.threshold.tolist(),
        "value": clf.tree_.value.tolist(),
    }
    json_path = os.path.join(MODEL_DIR, "decision_tree.json")
    with open(json_path, "w") as f:
        json.dump(tree_json, f, indent=2)
    print(f"  JSON exported → {json_path}")

    # Save pipeline
    path = os.path.join(MODEL_DIR, "decision_tree.joblib")
    joblib.dump(pipe, path)
    print(f"  Saved → {path}")

    return {
        "model": pipe,
        "accuracy": float(acc),
        "f1": float(f1),
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "latency_ms": float(latency_ms),
        "train_time_s": float(train_time),
        "model_path": path,
        "json_path": json_path,
    }


def train_isolation_forest(X_train, y_train, X_test, y_test):
    """Unsupervised anomaly detector: Isolation Forest."""
    _header("3 / 3  Isolation Forest (Anomaly Detector)")

    # Isolation Forest is trained only on NORMAL traffic
    X_train_normal = X_train[y_train == 0]
    print(f"  Training on {len(X_train_normal):,} normal samples (unsupervised)")

    scaler = StandardScaler()
    X_scaled_normal = scaler.fit_transform(X_train_normal)
    X_test_scaled   = scaler.transform(X_test)

    t0 = time.perf_counter()
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=SEED,
        n_jobs=-1,
    )
    iso.fit(X_scaled_normal)
    train_time = time.perf_counter() - t0

    # Predict: -1 = anomaly (attack), 1 = normal → remap to 0/1
    raw_pred = iso.predict(X_test_scaled)
    y_binary_pred = np.where(raw_pred == -1, 1, 0)   # 1 = attack detected
    y_binary_true = np.where(y_test > 0, 1, 0)        # 1 = actual attack

    acc = accuracy_score(y_binary_true, y_binary_pred)
    f1  = f1_score(y_binary_true, y_binary_pred, average="binary", zero_division=0)

    print(f"  Binary Accuracy : {acc:.4f}")
    print(f"  Binary F1       : {f1:.4f}")
    print(f"  Train time      : {train_time:.2f}s")

    # Latency
    single = X_test_scaled[[0]]
    times = []
    for _ in range(1000):
        t = time.perf_counter()
        iso.predict(single)
        times.append((time.perf_counter() - t) * 1000)
    latency_ms = np.median(times)
    print(f"  Infer latency   : {latency_ms:.3f} ms/sample (median)")

    # Save scaler + model as tuple
    path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
    joblib.dump((scaler, iso), path)
    print(f"  Saved → {path}")

    return {
        "model": (scaler, iso),
        "accuracy": float(acc),
        "f1": float(f1),
        "latency_ms": float(latency_ms),
        "train_time_s": float(train_time),
        "model_path": path,
    }


def save_summary(results: dict, X_test: pd.DataFrame):
    """Save training summary JSON for dashboard consumption."""
    summary = {}
    for name, r in results.items():
        summary[name] = {k: v for k, v in r.items() if k != "model"}

    # Model file sizes
    for name, r in results.items():
        path = r["model_path"]
        size_kb = os.path.getsize(path) / 1024
        summary[name]["size_kb"] = round(size_kb, 1)

    path = os.path.join(MODEL_DIR, "training_summary.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)

    _header("Training Summary")
    print(f"\n  {'Model':<22} {'Accuracy':>10} {'F1':>8} {'Latency':>10} {'Size':>8}")
    print(f"  {'─' * 62}")
    for name, s in summary.items():
        print(f"  {name:<22} {s['accuracy']:>9.4f} {s['f1']:>8.4f} "
              f"{s['latency_ms']:>8.3f}ms {s['size_kb']:>6.1f}KB")
    print(f"\n  Summary saved → {path}")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    _header("DoS Attack Detection — Model Training")

    # 1. Load data
    print("\n[1] Loading dataset …")
    df = load_or_generate_data()
    X = df[FEATURE_COLS]
    y = df[TARGET_COL]
    print(f"    Dataset: {len(df):,} samples  |  {X.shape[1]} features")
    print(f"    Classes: {dict(y.value_counts().sort_index())}")

    # 2. Train/test split — BEFORE any preprocessing
    print("\n[2] Splitting data (80% train / 20% test, stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=SEED
    )
    print(f"    Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # 3. Create model directory
    os.makedirs(MODEL_DIR, exist_ok=True)

    # 4. Train models
    results = {}
    results["Random Forest"]     = train_random_forest(X_train, y_train, X_test, y_test)
    results["Decision Tree"]     = train_decision_tree(X_train, y_train, X_test, y_test)
    results["Isolation Forest"]  = train_isolation_forest(X_train, y_train, X_test, y_test)

    # 5. Save summary
    save_summary(results, X_test)

    print(f"\n{'═' * 60}")
    print("  ✓ All models trained and saved successfully!")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    main()
