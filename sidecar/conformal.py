"""
Conformal calibration layer for Kernel Security Monitor.
Thresholds are PRECOMPUTED OFFLINE from a recorded benign corpus.
Do not fit live.
"""
import json
from pathlib import Path
from typing import Optional

import numpy as np


class ConformalCalibrator:
    """
    Conformal prediction wrapper using precomputed calibration scores.

    The calibration scores are anomaly scores from the Isolation Forest
    evaluated on a benign corpus (normal shell/build/web activity).
    The p-value for a new observation is the fraction of calibration scores
    that are at least as extreme.
    """

    def __init__(self, calibration_scores: Optional[np.ndarray] = None):
        self.calibration_scores = calibration_scores
        self.is_loaded = calibration_scores is not None and len(calibration_scores) > 0

    @classmethod
    def load(cls, path: Path) -> "ConformalCalibrator":
        """Load precomputed calibration scores from JSON."""
        with open(path) as f:
            data = json.load(f)
        scores = np.array(data["calibration_scores"], dtype=np.float64)
        return cls(calibration_scores=scores)

    @classmethod
    def empty(cls) -> "ConformalCalibrator":
        """Create an empty calibrator (returns conservative p-values)."""
        return cls(calibration_scores=None)

    def compute_p_value(self, anomaly_score: float) -> float:
        """
        Compute the conformal p-value for a new observation.

        p-value = (# calibration scores <= new score + 1) / (n + 1)

        This is the standard split conformal prediction formula.
        Lower p-value = more anomalous relative to the benign calibration set.
        """
        if not self.is_loaded:
            # Conservative: return 0.5 (uncertain) when no calibration data
            return 0.5

        n = len(self.calibration_scores)
        # Count how many calibration scores are at least as extreme (lower = more anomalous)
        count = np.sum(self.calibration_scores <= anomaly_score) + 1
        p_value = count / (n + 1)

        return float(np.clip(p_value, 0.0, 1.0))

    @staticmethod
    def tier_from_p_value(p_value: float) -> str:
        """
        Map conformal p-value to response tier.
        Thresholds are fixed constants, not fitted live.

        - low:    p > 0.15 — normal behavior, log only
        - medium: 0.05 < p <= 0.15 — suspicious, CRIU verify
        - high:   p <= 0.05 — highly anomalous, kill
        """
        if p_value > 0.15:
            return "low"
        elif p_value > 0.05:
            return "medium"
        else:
            return "high"

    def save(self, path: Path) -> None:
        """Save calibration scores to JSON."""
        data = {
            "calibration_scores": self.calibration_scores.tolist(),
            "n_scores": len(self.calibration_scores),
            "description": "Precomputed anomaly scores from benign corpus for conformal calibration",
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
