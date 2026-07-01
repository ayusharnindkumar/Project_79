"""
edge_optimizer.py — Edge Deployment Optimization for DoS Models
===============================================================
Reports model sizes, exports human-readable decision tree rules,
and provides a deployment guide for constrained edge devices.
"""

import os
import json
import time
import joblib
import numpy as np

MODEL_DIR = "models"

ATTACK_NAMES = {0: "Normal", 1: "SYN Flood", 2: "UDP Flood",
                3: "HTTP Flood", 4: "Smurf"}

EDGE_TARGETS = {
    "Raspberry Pi 4":       {"ram_mb": 4096, "cpu_cores": 4, "arch": "ARM Cortex-A72"},
    "Raspberry Pi Zero 2W": {"ram_mb": 512,  "cpu_cores": 4, "arch": "ARM Cortex-A53"},
    "ESP32 (MicroPython)":  {"ram_mb": 0.52, "cpu_cores": 1, "arch": "Xtensa LX6"},
    "NVIDIA Jetson Nano":   {"ram_mb": 4096, "cpu_cores": 4, "arch": "ARM Cortex-A57"},
}


def _header(title):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


def report_model_sizes():
    """Report file sizes for all trained model artifacts."""
    _header("Model Size Report")
    print(f"\n  {'Artifact':<35} {'Size':>10} {'Suitability'}")
    print(f"  {'─' * 65}")

    files = {
        "random_forest.joblib":       "Edge server / Pi 4",
        "decision_tree.joblib":       "Any edge device",
        "decision_tree.json":         "Browser / microcontroller",
        "decision_tree_rules.txt":    "Human audit / FPGA rules",
        "isolation_forest.joblib":    "Edge server / Pi 4",
        "training_summary.json":      "Dashboard / monitoring",
    }

    total = 0
    for fname, note in files.items():
        path = os.path.join(MODEL_DIR, fname)
        if os.path.exists(path):
            size_b = os.path.getsize(path)
            size_kb = size_b / 1024
            total += size_b
            bar = "█" * min(30, int(size_kb / 10))
            print(f"  {fname:<35} {size_kb:>7.1f} KB   {note}")
        else:
            print(f"  {fname:<35} {'MISSING':>10}   ← run train.py first")

    print(f"  {'─' * 65}")
    print(f"  {'TOTAL':<35} {total/1024:>7.1f} KB")


def benchmark_inference():
    """Benchmark inference speed for all models."""
    _header("Inference Latency Benchmark")

    rf  = joblib.load(os.path.join(MODEL_DIR, "random_forest.joblib"))
    dt  = joblib.load(os.path.join(MODEL_DIR, "decision_tree.joblib"))
    iso_scaler, iso = joblib.load(
        os.path.join(MODEL_DIR, "isolation_forest.joblib"))

    # Create a dummy sample
    dummy = np.random.randn(1, 15)
    import pandas as pd
    FEATURE_COLS = [
        "packet_rate", "byte_rate", "flow_duration", "avg_packet_size",
        "syn_ratio", "ack_ratio", "fin_ratio", "rst_ratio",
        "src_port_div", "dst_port_div", "inter_arrival", "payload_entropy",
        "is_tcp", "is_udp", "is_icmp",
    ]
    dummy_df = pd.DataFrame(dummy, columns=FEATURE_COLS)
    dummy_scaled = iso_scaler.transform(dummy_df)

    N = 10_000
    results = {}

    for model, name, sample in [
        (rf,  "Random Forest",    dummy_df),
        (dt,  "Decision Tree",    dummy_df),
        (iso, "Isolation Forest", dummy_scaled),
    ]:
        times = []
        for _ in range(N):
            t = time.perf_counter()
            model.predict(sample)
            times.append((time.perf_counter() - t) * 1_000_000)  # µs
        times = np.array(times)
        results[name] = times
        print(f"\n  {name}:")
        print(f"    Median  : {np.median(times):>8.2f} µs")
        print(f"    P95     : {np.percentile(times, 95):>8.2f} µs")
        print(f"    P99     : {np.percentile(times, 99):>8.2f} µs")
        print(f"    Max/s   : {1_000_000 / np.median(times):>8,.0f} inferences")

    return results


def print_dt_rules_summary():
    """Print the first 20 lines of decision tree rules."""
    _header("Decision Tree Rules (Human-Readable)")
    path = os.path.join(MODEL_DIR, "decision_tree_rules.txt")
    if os.path.exists(path):
        with open(path) as f:
            lines = f.readlines()[:25]
        print()
        for line in lines:
            print(f"  {line}", end="")
        if len(open(path).readlines()) > 25:
            print(f"\n  … (truncated, see {path} for full rules)")
    else:
        print("  Run train.py first to generate rules.")


def print_deployment_guide(latency_results: dict):
    """Print deployment recommendations per edge target."""
    _header("Edge Device Deployment Guide")

    dt_median_us  = np.median(latency_results.get("Decision Tree", [999]))
    rf_median_us  = np.median(latency_results.get("Random Forest", [9999]))

    print()
    for device, specs in EDGE_TARGETS.items():
        ram = specs["ram_mb"]
        scale = max(1, ram / 512)   # relative performance factor

        dt_est  = dt_median_us / scale
        rf_est  = rf_median_us / scale
        dt_fps  = 1_000_000 / dt_est
        rf_fps  = 1_000_000 / rf_est

        print(f"  ┌─ {device}")
        print(f"  │  CPU: {specs['arch']}")
        print(f"  │  RAM: {specs['ram_mb']} MB")
        print(f"  │  Decision Tree  → {dt_fps:>10,.0f} infer/s  ✓ Recommended")
        if ram >= 512:
            print(f"  │  Random Forest  → {rf_fps:>10,.0f} infer/s  ✓ Supported")
        else:
            print(f"  │  Random Forest  → {'N/A':>10}          ✗ Too large for RAM")
        print(f"  └{'─' * 50}")


def main():
    _header("EdgeGuard — Edge Deployment Optimizer")

    # Check models exist
    required = ["random_forest.joblib", "decision_tree.joblib",
                "isolation_forest.joblib"]
    missing = [f for f in required
               if not os.path.exists(os.path.join(MODEL_DIR, f))]
    if missing:
        print(f"\n  [!] Missing models: {missing}")
        print("      Run: python train.py  first\n")
        return

    report_model_sizes()
    latency = benchmark_inference()
    print_dt_rules_summary()
    print_deployment_guide(latency)

    print(f"\n{'═' * 60}")
    print("  ✓ Edge optimization report complete!")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    main()
