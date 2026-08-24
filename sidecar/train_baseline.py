"""
Offline training script for Kernel Security Monitor.
Generates:
  1. Isolation Forest model (data/isolation_forest_model.joblib)
  2. Calibration scores for conformal prediction (data/calibration_scores.json)
  3. Syscall n-gram baseline frequencies (data/ngram_baseline.json)

Run BEFORE the demo, not during it. This trains on synthetic benign activity
representing normal shell, build, and web-browsing patterns.
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from conformal import ConformalCalibrator

DATA_DIR = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def generate_benign_features(n_samples: int = 2000, seed: int = 42) -> np.ndarray:
    """
    Generate synthetic benign feature vectors representing normal activity.

    Features (no raw event counts — only structural/behavioral):
      0: fan_out_degree    — typical: 1-8 for normal processes
      1: edge_type_entropy — typical: 0.5-1.5 (some variety of syscalls)
      2: ngram_rarity      — typical: 0.1-0.4 (mostly seen patterns)
      3: ancestry_depth    — typical: 2-6 (bash → process → child)
    """
    rng = np.random.default_rng(seed)

    # Normal shell activity
    shell_n = n_samples // 3
    shell = np.column_stack([
        rng.poisson(lam=3, size=shell_n) + 1,        # fan_out: 1-7
        rng.uniform(0.5, 1.5, size=shell_n),          # entropy: moderate
        rng.uniform(0.05, 0.30, size=shell_n),        # ngram: common
        rng.integers(2, 5, size=shell_n).astype(float), # depth: 2-4
    ])

    # Build activity (make, gcc, etc.)
    build_n = n_samples // 3
    build = np.column_stack([
        rng.poisson(lam=6, size=build_n) + 2,        # fan_out: higher (parallel builds)
        rng.uniform(0.8, 2.0, size=build_n),          # entropy: higher variety
        rng.uniform(0.10, 0.35, size=build_n),        # ngram: somewhat common
        rng.integers(3, 7, size=build_n).astype(float), # depth: deeper
    ])

    # Web/curl activity
    web_n = n_samples - shell_n - build_n
    web = np.column_stack([
        rng.poisson(lam=2, size=web_n) + 1,           # fan_out: 1-5
        rng.uniform(0.3, 1.2, size=web_n),            # entropy: low-moderate
        rng.uniform(0.05, 0.25, size=web_n),           # ngram: common
        rng.integers(2, 5, size=web_n).astype(float),  # depth: 2-4
    ])

    return np.vstack([shell, build, web])


def generate_ngram_baseline(seed: int = 42) -> dict:
    """
    Generate synthetic n-gram baseline frequencies.
    Represents trigram frequencies observed during benign activity.
    """
    rng = np.random.default_rng(seed)

    syscall_types = ["execve", "openat", "connect", "read", "write", "close", "stat", "mmap", "mprotect", "brk"]

    trigrams = {}
    # Generate common trigrams from benign patterns
    benign_sequences = [
        ["execve", "openat", "read"],       # Normal program startup
        ["openat", "read", "close"],         # Normal file I/O
        ["execve", "openat", "write"],       # Normal program writing
        ["openat", "stat", "read"],          # File checking
        ["read", "write", "close"],          # Copy pattern
        ["execve", "mmap", "mprotect"],      # Dynamic linking
        ["mmap", "mprotect", "brk"],         # Memory setup
        ["stat", "openat", "read"],          # File access
        ["write", "close", "openat"],        # Sequential file writes
        ["read", "read", "read"],            # Streaming read
    ]

    # High-frequency benign trigrams
    for seq in benign_sequences:
        key = ",".join(seq)
        trigrams[key] = float(rng.uniform(0.6, 0.95))

    # Medium-frequency variations
    for _ in range(50):
        tri = [rng.choice(syscall_types) for _ in range(3)]
        key = ",".join(tri)
        if key not in trigrams:
            trigrams[key] = float(rng.uniform(0.2, 0.6))

    # Suspicious patterns (very low frequency in benign corpus)
    suspicious = [
        ["execve", "connect", "write"],     # Download and write
        ["write", "execve", "connect"],     # Stage, exec, callback
        ["execve", "execve", "connect"],    # Chain exec then connect
        ["openat", "write", "execve"],      # Write payload then exec
    ]
    for seq in suspicious:
        key = ",".join(seq)
        trigrams[key] = float(rng.uniform(0.01, 0.05))

    return trigrams


def train():
    print("[train] Generating benign feature vectors...")
    features = generate_benign_features(n_samples=2000)
    print(f"[train] Generated {len(features)} benign samples")
    print(f"[train] Feature stats:")
    for i, name in enumerate(["fan_out_degree", "edge_type_entropy", "ngram_rarity", "ancestry_depth"]):
        print(f"  {name}: mean={features[:, i].mean():.3f}, std={features[:, i].std():.3f}")

    # Train Isolation Forest
    print("[train] Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,  # Expect 3% contamination
        random_state=42,
        n_jobs=-1,
        max_features=4,
    )
    model.fit(features)

    model_path = DATA_DIR / "isolation_forest_model.joblib"
    joblib.dump(model, model_path)
    print(f"[train] Saved model to {model_path}")

    # Generate calibration scores for conformal prediction
    print("[train] Computing calibration scores on benign corpus...")
    calibration_scores = model.score_samples(features)
    calibrator = ConformalCalibrator(calibration_scores=calibration_scores)
    calibration_path = DATA_DIR / "calibration_scores.json"
    calibrator.save(calibration_path)
    print(f"[train] Saved {len(calibration_scores)} calibration scores to {calibration_path}")
    print(f"[train] Score range: [{calibration_scores.min():.4f}, {calibration_scores.max():.4f}]")
    print(f"[train] Score mean: {calibration_scores.mean():.4f}, std: {calibration_scores.std():.4f}")

    # Generate n-gram baseline
    print("[train] Generating n-gram baseline...")
    ngram_baseline = generate_ngram_baseline()
    ngram_path = DATA_DIR / "ngram_baseline.json"
    with open(ngram_path, "w") as f:
        json.dump(ngram_baseline, f, indent=2)
    print(f"[train] Saved {len(ngram_baseline)} n-gram frequencies to {ngram_path}")

    # Verify the model with some test cases
    print("\n[train] Verification:")

    # Normal case
    normal = np.array([[3.0, 1.0, 0.15, 3.0]])
    normal_pred = model.predict(normal)[0]
    normal_score = model.score_samples(normal)[0]
    normal_pval = calibrator.compute_p_value(normal_score)
    print(f"  Normal case:   pred={normal_pred:+d}, score={normal_score:.4f}, p={normal_pval:.4f}, tier={calibrator.tier_from_p_value(normal_pval)}")

    # Suspicious case (high fan-out, high rarity)
    suspicious = np.array([[15.0, 2.5, 0.85, 8.0]])
    sus_pred = model.predict(suspicious)[0]
    sus_score = model.score_samples(suspicious)[0]
    sus_pval = calibrator.compute_p_value(sus_score)
    print(f"  Suspicious:    pred={sus_pred:+d}, score={sus_score:.4f}, p={sus_pval:.4f}, tier={calibrator.tier_from_p_value(sus_pval)}")

    # Highly anomalous (extreme values)
    anomalous = np.array([[30.0, 3.0, 0.95, 12.0]])
    anom_pred = model.predict(anomalous)[0]
    anom_score = model.score_samples(anomalous)[0]
    anom_pval = calibrator.compute_p_value(anom_score)
    print(f"  Anomalous:     pred={anom_pred:+d}, score={anom_score:.4f}, p={anom_pval:.4f}, tier={calibrator.tier_from_p_value(anom_pval)}")

    print("\n[train] Done! All artifacts saved to data/")


if __name__ == "__main__":
    train()
