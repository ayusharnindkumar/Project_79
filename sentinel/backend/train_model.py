"""
train_model.py — Logistic Regression Training on NSL-KDD-style Data
=====================================================================
Generates synthetic NSL-KDD-style traffic data, trains a Logistic Regression
classifier with a tuned decision threshold, and saves the model artifacts.

Run once before starting the API server:
    python train_model.py

Outputs:
    model.pkl   — sklearn Pipeline (preprocessor + LogisticRegression)
    threshold   — stored inside model.pkl as 'threshold' key
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline     import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics       import classification_report, roc_auc_score

from preprocessing import (
    build_preprocessor,
    ALL_FEATURES, CATEGORICAL_FEATURES, NUMERICAL_FEATURES,
)

RNG  = np.random.default_rng(42)
BASE = os.path.dirname(os.path.abspath(__file__))

# ── Decision threshold (tuned to minimize false negatives) ───────────────────
THRESHOLD = 0.45


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data generation
# ─────────────────────────────────────────────────────────────────────────────

def _clip(arr, lo, hi):
    return np.clip(arr, lo, hi)


def gen_normal(n: int) -> pd.DataFrame:
    """Generate realistic normal (benign) traffic samples."""
    proto   = RNG.choice(['tcp', 'tcp', 'tcp', 'udp', 'icmp'],    size=n)
    svc     = RNG.choice(['http', 'ftp_data', 'smtp', 'ssh', 'auth', 'domain_u', 'finger', 'other', 'pop_3', 'ftp'], size=n)
    flag    = RNG.choice(['SF', 'SF', 'SF', 'SF', 'REJ', 'RSTO'], size=n)

    rows = pd.DataFrame({
        'protocol_type':         proto,
        'service':               svc,
        'flag':                  flag,
        'src_bytes':             _clip(RNG.exponential(3000,  n), 0, 500_000).astype(float),
        'dst_bytes':             _clip(RNG.exponential(5000,  n), 0, 800_000).astype(float),
        'duration':              _clip(RNG.exponential(30,    n), 0, 3000   ).astype(float),
        'land':                  np.zeros(n,  dtype=int),
        'wrong_fragment':        np.zeros(n,  dtype=int),
        'urgent':                np.zeros(n,  dtype=int),
        'count':                 RNG.integers(1, 100, n).astype(float),
        'srv_count':             RNG.integers(1, 100, n).astype(float),
        'serror_rate':           _clip(RNG.normal(0.01, 0.03,  n), 0, 1),
        'srv_serror_rate':       _clip(RNG.normal(0.01, 0.03,  n), 0, 1),
        'rerror_rate':           _clip(RNG.normal(0.01, 0.03,  n), 0, 1),
        'same_srv_rate':         _clip(RNG.beta(8, 2,           n), 0, 1),
        'diff_srv_rate':         _clip(RNG.beta(2, 8,           n), 0, 1),
        'srv_diff_host_rate':    _clip(RNG.beta(1, 4,           n), 0, 1),
        'dst_host_count':        RNG.integers(50, 255, n).astype(float),
        'dst_host_srv_count':    RNG.integers(30, 255, n).astype(float),
        'dst_host_same_srv_rate':_clip(RNG.beta(6, 2,           n), 0, 1),
        'dst_host_serror_rate':  _clip(RNG.normal(0.01, 0.02,   n), 0, 1),
        'logged_in':             RNG.choice([0, 1], p=[0.3, 0.7], size=n).astype(float),
        'label':                 0,
    })
    return rows


def gen_neptune(n: int) -> pd.DataFrame:
    """TCP SYN flood — dominant DoS type in NSL-KDD."""
    return pd.DataFrame({
        'protocol_type':         ['tcp']   * n,
        'service':               RNG.choice(['http', 'private', 'domain_u', 'smtp'], size=n).tolist(),
        'flag':                  ['S0']    * n,
        'src_bytes':             np.zeros(n, dtype=float),
        'dst_bytes':             np.zeros(n, dtype=float),
        'duration':              np.zeros(n, dtype=float),
        'land':                  np.zeros(n, dtype=int),
        'wrong_fragment':        np.zeros(n, dtype=int),
        'urgent':                np.zeros(n, dtype=int),
        'count':                 np.full(n, 511, dtype=float),
        'srv_count':             np.full(n, 511, dtype=float),
        'serror_rate':           np.ones(n, dtype=float),
        'srv_serror_rate':       np.ones(n, dtype=float),
        'rerror_rate':           np.zeros(n, dtype=float),
        'same_srv_rate':         np.ones(n, dtype=float),
        'diff_srv_rate':         np.zeros(n, dtype=float),
        'srv_diff_host_rate':    np.zeros(n, dtype=float),
        'dst_host_count':        np.full(n, 255, dtype=float),
        'dst_host_srv_count':    np.full(n, 255, dtype=float),
        'dst_host_same_srv_rate':np.ones(n, dtype=float),
        'dst_host_serror_rate':  np.ones(n, dtype=float),
        'logged_in':             np.zeros(n, dtype=float),
        'label':                 1,
    })


def gen_smurf(n: int) -> pd.DataFrame:
    """ICMP broadcast amplification attack."""
    sizes = RNG.choice([936, 1032], size=n).astype(float)
    return pd.DataFrame({
        'protocol_type':         ['icmp']  * n,
        'service':               ['ecr_i'] * n,
        'flag':                  ['SF']    * n,
        'src_bytes':             sizes,
        'dst_bytes':             sizes,
        'duration':              np.zeros(n, dtype=float),
        'land':                  np.zeros(n, dtype=int),
        'wrong_fragment':        np.zeros(n, dtype=int),
        'urgent':                np.zeros(n, dtype=int),
        'count':                 np.full(n, 511, dtype=float),
        'srv_count':             np.full(n, 511, dtype=float),
        'serror_rate':           np.zeros(n, dtype=float),
        'srv_serror_rate':       np.zeros(n, dtype=float),
        'rerror_rate':           np.zeros(n, dtype=float),
        'same_srv_rate':         np.ones(n, dtype=float),
        'diff_srv_rate':         np.zeros(n, dtype=float),
        'srv_diff_host_rate':    np.zeros(n, dtype=float),
        'dst_host_count':        np.full(n, 255, dtype=float),
        'dst_host_srv_count':    np.full(n, 255, dtype=float),
        'dst_host_same_srv_rate':np.ones(n, dtype=float),
        'dst_host_serror_rate':  np.zeros(n, dtype=float),
        'logged_in':             np.zeros(n, dtype=float),
        'label':                 1,
    })


def gen_teardrop(n: int) -> pd.DataFrame:
    """UDP fragmentation attack."""
    return pd.DataFrame({
        'protocol_type':         ['udp']    * n,
        'service':               ['private']* n,
        'flag':                  ['SF']     * n,
        'src_bytes':             _clip(RNG.integers(20, 100, n), 0, 1500).astype(float),
        'dst_bytes':             np.zeros(n, dtype=float),
        'duration':              np.zeros(n, dtype=float),
        'land':                  np.zeros(n, dtype=int),
        'wrong_fragment':        RNG.integers(1, 4, n).astype(int),
        'urgent':                np.zeros(n, dtype=int),
        'count':                 _clip(RNG.integers(1, 20, n), 1, 511).astype(float),
        'srv_count':             _clip(RNG.integers(1, 20, n), 1, 511).astype(float),
        'serror_rate':           np.zeros(n, dtype=float),
        'srv_serror_rate':       np.zeros(n, dtype=float),
        'rerror_rate':           np.zeros(n, dtype=float),
        'same_srv_rate':         _clip(RNG.beta(2, 1, n), 0, 1),
        'diff_srv_rate':         _clip(RNG.beta(1, 2, n), 0, 1),
        'srv_diff_host_rate':    np.zeros(n, dtype=float),
        'dst_host_count':        _clip(RNG.integers(1, 50, n), 1, 255).astype(float),
        'dst_host_srv_count':    _clip(RNG.integers(1, 30, n), 1, 255).astype(float),
        'dst_host_same_srv_rate':_clip(RNG.beta(2, 1, n), 0, 1),
        'dst_host_serror_rate':  np.zeros(n, dtype=float),
        'logged_in':             np.zeros(n, dtype=float),
        'label':                 1,
    })


def gen_back(n: int) -> pd.DataFrame:
    """HTTP back-door overload attack."""
    return pd.DataFrame({
        'protocol_type':         ['tcp']  * n,
        'service':               ['http'] * n,
        'flag':                  ['SF']   * n,
        'src_bytes':             _clip(RNG.integers(100, 600, n),    0, 5000).astype(float),
        'dst_bytes':             _clip(RNG.integers(50000, 120000, n), 0, 1_000_000).astype(float),
        'duration':              _clip(RNG.exponential(1, n), 0, 20).astype(float),
        'land':                  np.zeros(n, dtype=int),
        'wrong_fragment':        np.zeros(n, dtype=int),
        'urgent':                np.zeros(n, dtype=int),
        'count':                 _clip(RNG.integers(1, 30, n), 1, 511).astype(float),
        'srv_count':             _clip(RNG.integers(1, 30, n), 1, 511).astype(float),
        'serror_rate':           _clip(RNG.normal(0.02, 0.05, n), 0, 1),
        'srv_serror_rate':       _clip(RNG.normal(0.02, 0.05, n), 0, 1),
        'rerror_rate':           np.zeros(n, dtype=float),
        'same_srv_rate':         np.ones(n, dtype=float),
        'diff_srv_rate':         np.zeros(n, dtype=float),
        'srv_diff_host_rate':    np.zeros(n, dtype=float),
        'dst_host_count':        _clip(RNG.integers(100, 255, n), 0, 255).astype(float),
        'dst_host_srv_count':    _clip(RNG.integers(100, 255, n), 0, 255).astype(float),
        'dst_host_same_srv_rate':np.ones(n, dtype=float),
        'dst_host_serror_rate':  _clip(RNG.normal(0.01, 0.03, n), 0, 1),
        'logged_in':             np.ones(n, dtype=float),
        'label':                 1,
    })


def gen_pod(n: int) -> pd.DataFrame:
    """ICMP Ping-of-Death (oversized packets)."""
    return pd.DataFrame({
        'protocol_type':         ['icmp'] * n,
        'service':               RNG.choice(['ecr_i', 'eco_i', 'other'], size=n).tolist(),
        'flag':                  ['SF']   * n,
        'src_bytes':             np.full(n, 1480, dtype=float),
        'dst_bytes':             np.full(n, 1480, dtype=float),
        'duration':              np.zeros(n, dtype=float),
        'land':                  np.zeros(n, dtype=int),
        'wrong_fragment':        np.zeros(n, dtype=int),
        'urgent':                np.zeros(n, dtype=int),
        'count':                 _clip(RNG.integers(1, 50, n), 1, 511).astype(float),
        'srv_count':             _clip(RNG.integers(1, 50, n), 1, 511).astype(float),
        'serror_rate':           np.zeros(n, dtype=float),
        'srv_serror_rate':       np.zeros(n, dtype=float),
        'rerror_rate':           np.zeros(n, dtype=float),
        'same_srv_rate':         np.ones(n, dtype=float),
        'diff_srv_rate':         np.zeros(n, dtype=float),
        'srv_diff_host_rate':    np.zeros(n, dtype=float),
        'dst_host_count':        _clip(RNG.integers(100, 255, n), 0, 255).astype(float),
        'dst_host_srv_count':    _clip(RNG.integers(100, 255, n), 0, 255).astype(float),
        'dst_host_same_srv_rate':np.ones(n, dtype=float),
        'dst_host_serror_rate':  np.zeros(n, dtype=float),
        'logged_in':             np.zeros(n, dtype=float),
        'label':                 1,
    })


def generate_dataset() -> pd.DataFrame:
    print("  Generating Normal traffic …")
    normal   = gen_normal(5000)
    print("  Generating Neptune (SYN Flood) …")
    neptune  = gen_neptune(2500)
    print("  Generating Smurf (ICMP Flood) …")
    smurf    = gen_smurf(1500)
    print("  Generating Teardrop (UDP Frag) …")
    teardrop = gen_teardrop(500)
    print("  Generating Back (HTTP Flood) …")
    back     = gen_back(400)
    print("  Generating Pod (Ping-of-Death) …")
    pod      = gen_pod(300)

    df = pd.concat([normal, neptune, smurf, teardrop, back, pod], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Sentinel — Model Training (Logistic Regression on NSL-KDD)")
    print("=" * 60)

    print("\n[1] Generating synthetic NSL-KDD-style dataset …")
    df = generate_dataset()
    X  = df[ALL_FEATURES]
    y  = df['label'].astype(int)
    print(f"    Total: {len(df):,} samples  |  Normal: {(y==0).sum():,}  |  DoS: {(y==1).sum():,}")

    print("\n[2] Train / test split (80 / 20, stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\n[3] Building pipeline …")
    pipeline = Pipeline([
        ('preprocessor', build_preprocessor()),
        ('classifier',   LogisticRegression(C=1.0, max_iter=1000, random_state=42, n_jobs=-1)),
    ])

    print("\n[4] 5-fold cross-validation …")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring='f1', n_jobs=-1)
    print(f"    CV F1 : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    print("\n[5] Fitting final model …")
    pipeline.fit(X_train, y_train)

    print("\n[6] Evaluating on held-out test set …")
    proba     = pipeline.predict_proba(X_test)[:, 1]
    y_pred    = (proba >= THRESHOLD).astype(int)
    auc       = roc_auc_score(y_test, proba)
    print(f"    AUC-ROC: {auc:.4f}  |  Threshold: {THRESHOLD}")
    print()
    print(classification_report(y_test, y_pred, target_names=['Normal', 'DoS Attack']))

    print("\n[7] Saving model artifacts …")
    artifact = {
        'pipeline':  pipeline,
        'threshold': THRESHOLD,
        'features':  ALL_FEATURES,
        'cat_features': CATEGORICAL_FEATURES,
        'num_features': NUMERICAL_FEATURES,
    }
    out_path = os.path.join(BASE, 'model.pkl')
    joblib.dump(artifact, out_path)
    size_kb = os.path.getsize(out_path) / 1024
    print(f"    model.pkl saved → {out_path}  ({size_kb:.1f} KB)")

    meta = {
        'cv_f1_mean': float(cv_scores.mean()),
        'cv_f1_std':  float(cv_scores.std()),
        'auc_roc':    float(auc),
        'threshold':  THRESHOLD,
        'n_train':    int(len(X_train)),
        'n_test':     int(len(X_test)),
    }
    with open(os.path.join(BASE, 'model_meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    print("\n" + "=" * 60)
    print("  ✓ Training complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
