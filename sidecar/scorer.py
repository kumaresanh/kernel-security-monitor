"""
Kernel Security Monitor Python Sidecar — Isolation Forest scorer with conformal calibration.
Communicates with Go control plane via HTTP (Unix socket or TCP).
"""
import json
import os
import sys
from pathlib import Path

import numpy as np
import joblib
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from conformal import ConformalCalibrator

from contextlib import asynccontextmanager

# Paths
DATA_DIR = Path(__file__).parent.parent / "data"
MODEL_PATH = DATA_DIR / "isolation_forest_model.joblib"
CALIBRATION_PATH = DATA_DIR / "calibration_scores.json"

# Globals (loaded at startup)
model = None
calibrator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, calibrator

    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        print(f"[scorer] Loaded Isolation Forest model from {MODEL_PATH}")
    else:
        print(f"[scorer] WARNING: Model not found at {MODEL_PATH}, run train_baseline.py first")

    if CALIBRATION_PATH.exists():
        calibrator = ConformalCalibrator.load(CALIBRATION_PATH)
        print(f"[scorer] Loaded conformal calibrator from {CALIBRATION_PATH}")
    else:
        print(f"[scorer] WARNING: Calibration scores not found at {CALIBRATION_PATH}")
        calibrator = ConformalCalibrator.empty()

    yield


class FeatureVector(BaseModel):
    fan_out_degree: float
    edge_type_entropy: float
    ngram_rarity: float
    ancestry_depth: float


class ScoringRequest(BaseModel):
    pid: int
    features: FeatureVector


class ScoringResponse(BaseModel):
    pid: int
    anomaly_score: float  # Isolation Forest decision function value
    raw_score: float      # Raw anomaly score
    is_anomaly: bool      # IF prediction (-1 = anomaly)
    p_value: float        # Conformal p-value
    tier: str             # low / medium / high
    features: dict


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    calibrator_loaded: bool


app = FastAPI(title="Kernel Security Monitor Scorer", lifespan=lifespan)



@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        model_loaded=model is not None,
        calibrator_loaded=calibrator is not None and calibrator.is_loaded,
    )


@app.post("/score", response_model=ScoringResponse)
def score(req: ScoringRequest):
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    features = np.array([[
        req.features.fan_out_degree,
        req.features.edge_type_entropy,
        req.features.ngram_rarity,
        req.features.ancestry_depth,
    ]])

    # Isolation Forest prediction
    prediction = int(model.predict(features)[0])
    decision_score = float(model.decision_function(features)[0])
    anomaly_score = float(model.score_samples(features)[0])

    is_anomaly = prediction == -1

    # Conformal calibration — thresholds are PRECOMPUTED OFFLINE
    p_value = calibrator.compute_p_value(anomaly_score)
    tier = calibrator.tier_from_p_value(p_value)

    return ScoringResponse(
        pid=req.pid,
        anomaly_score=round(decision_score, 6),
        raw_score=round(anomaly_score, 6),
        is_anomaly=is_anomaly,
        p_value=round(p_value, 6),
        tier=tier,
        features={
            "fan_out_degree": req.features.fan_out_degree,
            "edge_type_entropy": req.features.edge_type_entropy,
            "ngram_rarity": req.features.ngram_rarity,
            "ancestry_depth": req.features.ancestry_depth,
        },
    )


import subprocess

if __name__ == "__main__":
    port = int(os.environ.get("SCORER_PORT", "8099"))

    # Auto-release port if lingering from previous run
    try:
        subprocess.run(["fuser", "-k", f"{port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except Exception:
        pass

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")

