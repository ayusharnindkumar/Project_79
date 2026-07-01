"""
data_generator.py — Synthetic DoS Traffic Dataset Generator
============================================================
Generates realistic network traffic data with 15 edge-ML-ready features
for training DoS attack detection models.

Traffic Classes:
  0 — Normal
  1 — SYN Flood   (TCP SYN packet storm)
  2 — UDP Flood   (high-rate UDP packet burst)
  3 — HTTP Flood  (application-layer GET/POST flood)
  4 — Smurf       (ICMP broadcast amplification)

Features (15 total):
  packet_rate      — packets per second arriving at edge device
  byte_rate        — bytes per second (throughput)
  flow_duration    — duration of the flow in milliseconds
  avg_packet_size  — average payload size in bytes
  syn_ratio        — ratio of SYN-flagged packets
  ack_ratio        — ratio of ACK-flagged packets
  fin_ratio        — ratio of FIN-flagged packets
  rst_ratio        — ratio of RST-flagged packets
  src_port_div     — source port diversity (entropy-normalized 0-1)
  dst_port_div     — destination port diversity (entropy-normalized 0-1)
  inter_arrival    — mean inter-packet arrival time (ms)
  payload_entropy  — Shannon entropy of payload bytes (0-8)
  is_tcp           — 1 if flow is TCP, else 0
  is_udp           — 1 if flow is UDP, else 0
  is_icmp          — 1 if flow is ICMP, else 0
"""

import numpy as np
import pandas as pd
import os

# ── reproducibility ──────────────────────────────────────────────────────────
SEED = 42
rng = np.random.default_rng(SEED)

# ── class distribution ───────────────────────────────────────────────────────
N_SAMPLES = 10_000
CLASS_WEIGHTS = {
    0: 0.50,   # Normal      — 5 000 samples
    1: 0.20,   # SYN Flood   — 2 000 samples
    2: 0.15,   # UDP Flood   — 1 500 samples
    3: 0.10,   # HTTP Flood  — 1 000 samples
    4: 0.05,   # Smurf       —   500 samples
}

FEATURE_COLS = [
    "packet_rate", "byte_rate", "flow_duration", "avg_packet_size",
    "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
    "src_port_div", "dst_port_div", "inter_arrival", "payload_entropy",
    "is_tcp", "is_udp", "is_icmp",
]
TARGET_COL = "label"
ATTACK_NAMES = {0: "Normal", 1: "SYN Flood", 2: "UDP Flood",
                3: "HTTP Flood", 4: "Smurf"}


# ── per-class feature distributions ──────────────────────────────────────────

def _normal(n):
    return pd.DataFrame({
        "packet_rate":     rng.normal(120, 40, n).clip(10, 600),
        "byte_rate":       rng.normal(15_000, 5_000, n).clip(500, 60_000),
        "flow_duration":   rng.exponential(500, n).clip(10, 5_000),
        "avg_packet_size": rng.normal(800, 200, n).clip(64, 1_500),
        "syn_ratio":       rng.beta(1, 8, n),
        "ack_ratio":       rng.beta(6, 2, n),
        "fin_ratio":       rng.beta(2, 8, n),
        "rst_ratio":       rng.beta(1, 15, n),
        "src_port_div":    rng.beta(5, 2, n),
        "dst_port_div":    rng.beta(5, 2, n),
        "inter_arrival":   rng.exponential(20, n).clip(1, 200),
        "payload_entropy": rng.normal(5.5, 1.2, n).clip(0, 8),
        "is_tcp":          rng.binomial(1, 0.65, n),
        "is_udp":          rng.binomial(1, 0.25, n),
        "is_icmp":         rng.binomial(1, 0.10, n),
        TARGET_COL: 0,
    })


def _syn_flood(n):
    return pd.DataFrame({
        "packet_rate":     rng.normal(4_500, 800, n).clip(800, 10_000),
        "byte_rate":       rng.normal(200_000, 50_000, n).clip(50_000, 500_000),
        "flow_duration":   rng.exponential(50, n).clip(5, 300),
        "avg_packet_size": rng.normal(60, 10, n).clip(40, 100),   # tiny SYN pkts
        "syn_ratio":       rng.beta(18, 1, n),                    # ~0.95 SYN
        "ack_ratio":       rng.beta(1, 20, n),                    # almost no ACK
        "fin_ratio":       rng.beta(1, 30, n),
        "rst_ratio":       rng.beta(2, 10, n),
        "src_port_div":    rng.beta(8, 1, n),                     # many src ports (spoofed)
        "dst_port_div":    rng.beta(1, 15, n),                    # single dst port
        "inter_arrival":   rng.exponential(0.5, n).clip(0.05, 5),
        "payload_entropy": rng.normal(1.5, 0.5, n).clip(0, 3),   # low entropy
        "is_tcp":          np.ones(n),
        "is_udp":          np.zeros(n),
        "is_icmp":         np.zeros(n),
        TARGET_COL: 1,
    })


def _udp_flood(n):
    return pd.DataFrame({
        "packet_rate":     rng.normal(3_000, 600, n).clip(500, 8_000),
        "byte_rate":       rng.normal(500_000, 100_000, n).clip(100_000, 1_200_000),
        "flow_duration":   rng.exponential(80, n).clip(5, 500),
        "avg_packet_size": rng.normal(1_400, 50, n).clip(1_000, 1_500),  # jumbo UDP
        "syn_ratio":       rng.beta(1, 30, n),
        "ack_ratio":       rng.beta(1, 30, n),
        "fin_ratio":       rng.beta(1, 30, n),
        "rst_ratio":       rng.beta(1, 30, n),
        "src_port_div":    rng.beta(7, 1, n),
        "dst_port_div":    rng.beta(7, 1, n),
        "inter_arrival":   rng.exponential(1, n).clip(0.05, 10),
        "payload_entropy": rng.normal(7.5, 0.3, n).clip(6, 8),    # high entropy (random payload)
        "is_tcp":          np.zeros(n),
        "is_udp":          np.ones(n),
        "is_icmp":         np.zeros(n),
        TARGET_COL: 2,
    })


def _http_flood(n):
    return pd.DataFrame({
        "packet_rate":     rng.normal(600, 150, n).clip(100, 2_000),
        "byte_rate":       rng.normal(80_000, 20_000, n).clip(10_000, 300_000),
        "flow_duration":   rng.normal(2_000, 500, n).clip(500, 8_000),
        "avg_packet_size": rng.normal(700, 150, n).clip(300, 1_400),
        "syn_ratio":       rng.beta(3, 5, n),
        "ack_ratio":       rng.beta(7, 2, n),
        "fin_ratio":       rng.beta(3, 5, n),
        "rst_ratio":       rng.beta(1, 10, n),
        "src_port_div":    rng.beta(2, 8, n),                      # few src ports
        "dst_port_div":    rng.beta(1, 20, n),                     # port 80/443 only
        "inter_arrival":   rng.exponential(5, n).clip(0.5, 50),
        "payload_entropy": rng.normal(6.8, 0.4, n).clip(5, 8),    # structured HTTP
        "is_tcp":          np.ones(n),
        "is_udp":          np.zeros(n),
        "is_icmp":         np.zeros(n),
        TARGET_COL: 3,
    })


def _smurf(n):
    return pd.DataFrame({
        "packet_rate":     rng.normal(2_000, 400, n).clip(300, 6_000),
        "byte_rate":       rng.normal(120_000, 30_000, n).clip(20_000, 400_000),
        "flow_duration":   rng.exponential(30, n).clip(5, 200),
        "avg_packet_size": rng.normal(1_000, 50, n).clip(800, 1_200),  # large ICMP echo
        "syn_ratio":       rng.beta(1, 30, n),
        "ack_ratio":       rng.beta(1, 30, n),
        "fin_ratio":       rng.beta(1, 30, n),
        "rst_ratio":       rng.beta(1, 30, n),
        "src_port_div":    rng.beta(1, 20, n),                     # broadcast src
        "dst_port_div":    rng.beta(1, 20, n),
        "inter_arrival":   rng.exponential(2, n).clip(0.1, 20),
        "payload_entropy": rng.normal(3.0, 0.8, n).clip(0, 5),
        "is_tcp":          np.zeros(n),
        "is_udp":          np.zeros(n),
        "is_icmp":         np.ones(n),
        TARGET_COL: 4,
    })


# ── main generator ────────────────────────────────────────────────────────────

def generate_dataset(n_samples: int = N_SAMPLES, output_path: str = None) -> pd.DataFrame:
    """Generate and return a synthetic DoS detection dataset.

    Args:
        n_samples:   Total number of samples to generate.
        output_path: If provided, saves the CSV to this path.

    Returns:
        pd.DataFrame with feature columns + 'label' column.
    """
    generators = {0: _normal, 1: _syn_flood, 2: _udp_flood,
                  3: _http_flood, 4: _smurf}

    frames = []
    for label, weight in CLASS_WEIGHTS.items():
        n = int(n_samples * weight)
        df = generators[label](n)
        frames.append(df)

    dataset = pd.concat(frames, ignore_index=True)

    # Fix protocol one-hot: ensure no sample has is_tcp + is_udp both = 1
    # (Smurf/UDP generators already set this correctly; normal may have overlap)
    mask_tcp = dataset["is_tcp"] == 1
    mask_udp = dataset["is_udp"] == 1
    overlap = mask_tcp & mask_udp
    dataset.loc[overlap, "is_udp"] = 0  # prefer TCP on overlap

    # Shuffle
    dataset = dataset.sample(frac=1, random_state=SEED).reset_index(drop=True)

    # Add attack name column for readability
    dataset["attack_type"] = dataset[TARGET_COL].map(ATTACK_NAMES)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        dataset.to_csv(output_path, index=False)
        print(f"[✓] Dataset saved → {output_path}")

    return dataset


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  DoS Detection — Synthetic Dataset Generator")
    print("=" * 60)

    df = generate_dataset(
        n_samples=N_SAMPLES,
        output_path="data/dos_traffic.csv"
    )

    print(f"\n{'Class':<14} {'Count':>8} {'%':>6}")
    print("-" * 32)
    for label, name in ATTACK_NAMES.items():
        count = (df["label"] == label).sum()
        pct = count / len(df) * 100
        print(f"{name:<14} {count:>8,} {pct:>5.1f}%")

    print(f"\n{'─' * 32}")
    print(f"  Total samples : {len(df):,}")
    print(f"  Features      : {len(FEATURE_COLS)}")
    print(f"  Positive rate : {(df['label'] > 0).mean():.1%}")
    print(f"\nFeature stats:")
    print(df[FEATURE_COLS].describe().round(2).to_string())
