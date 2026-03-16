"""
The Agentic SOC - Phase 3: API Backend (Flask)

Responsibilities:
- POST /api/ingest: receive a log event, run ML anomaly detection, and (if anomalous)
  call Claude reasoning to decide containment and produce narrative/ROI/YARA.
- Mock containment action endpoints (network isolation, token revocation, honeypot).
- POST /api/contain/undo/<incident_id>: undo a containment action.
- GET /api/state: expose current incident state to the frontend.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template

from claude_reasoning import analyze_anomaly
from train_model import build_features


BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "anomaly_rf_model.joblib"
ENCODERS_PATH = MODELS_DIR / "encoders.joblib"


load_dotenv(override=False)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Model loading and feature pipeline
# ---------------------------------------------------------------------------
clf = joblib.load(MODEL_PATH)
encoders_meta: Dict[str, Any] = joblib.load(ENCODERS_PATH)
FEATURE_COLUMNS: List[str] = encoders_meta.get("feature_columns", [])


def _ensure_log_defaults(log: Dict[str, Any]) -> Dict[str, Any]:
    """Fill in missing keys with safe defaults so build_features works."""
    out = dict(log)
    out.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    out.setdefault("source_ip", "10.0.0.1")
    out.setdefault("dest_ip", "10.0.0.2")
    out.setdefault("src_port", 50000)
    out.setdefault("dest_port", 443)
    out.setdefault("protocol", "HTTPS")
    out.setdefault("user_id", "user_0001")
    out.setdefault("asset_id", "host-app1")
    out.setdefault("action", "connection")
    out.setdefault("outcome", "success")
    out.setdefault("bytes_sent", 0)
    out.setdefault("duration_sec", 0.1)
    out.setdefault("attack_type", log.get("attack_type") or None)
    return out


def score_log_with_model(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the trained RandomForest on a single log.
    Returns prediction (0/1) and anomaly probability.
    """
    normalized = _ensure_log_defaults(log)
    df = pd.DataFrame([normalized])
    X = build_features(df)
    # Reorder/align columns to training order if necessary
    if FEATURE_COLUMNS:
        for col in FEATURE_COLUMNS:
            if col not in X.columns:
                X[col] = 0
        X = X[FEATURE_COLUMNS]
    X = X.fillna(0)
    proba = float(clf.predict_proba(X)[0][1])
    pred = int(proba >= 0.5)
    return {"prediction": pred, "probability": proba, "normalized_log": normalized}


# ---------------------------------------------------------------------------
# In-memory incident state
# ---------------------------------------------------------------------------
INCIDENTS: Dict[str, Dict[str, Any]] = {}
TOTAL_ROI_SAVED: float = 0.0
_INCIDENT_COUNTER = 0


def _new_incident_id() -> str:
    global _INCIDENT_COUNTER
    _INCIDENT_COUNTER += 1
    return f"INC-{_INCIDENT_COUNTER:05d}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index() -> Any:
    """Serve the Agentic SOC dashboard UI."""
    return render_template("index.html")


@app.route("/api/ingest", methods=["POST"])
def ingest() -> Any:
    """
    Receive a log event and run ML -> Claude pipeline.
    Returns an incident object if anomalous, or a normal-response otherwise.
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    if not isinstance(payload, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    ml_result = score_log_with_model(payload)
    is_anomaly = ml_result["prediction"] == 1

    if not is_anomaly:
        return jsonify(
            {
                "status": "normal",
                "ml_prediction": 0,
                "ml_probability": ml_result["probability"],
                "message": "Event scored as normal traffic.",
            }
        )

    anomaly_log = ml_result["normalized_log"]

    # If attack_type not set, infer a simple label for Claude context
    if not anomaly_log.get("attack_type"):
        if anomaly_log.get("protocol") in ("SMB", "RDP", "SSH"):
            anomaly_log["attack_type"] = "lateral_movement"
        else:
            anomaly_log["attack_type"] = "stolen_token"

    llm_result = analyze_anomaly(anomaly_log)

    global TOTAL_ROI_SAVED
    roi = float(llm_result.get("estimated_roi_saved", 0) or 0)
    TOTAL_ROI_SAVED += max(roi, 0.0)

    incident_id = _new_incident_id()
    incident = {
        "incident_id": incident_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "log": anomaly_log,
        "ml_prediction": ml_result["prediction"],
        "ml_probability": ml_result["probability"],
        "containment_action": llm_result["containment_action"],
        "play_by_play_narrative": llm_result["play_by_play_narrative"],
        "estimated_roi_saved": llm_result["estimated_roi_saved"],
        "generated_yara_rule": llm_result["generated_yara_rule"],
        "interrogation_log": llm_result["interrogation_log"],
        "status": "contained",
    }
    INCIDENTS[incident_id] = incident

    return jsonify(
        {
            "status": "anomaly",
            "incident": incident,
            "total_roi_saved": TOTAL_ROI_SAVED,
        }
    )


@app.route("/api/action/isolate", methods=["POST"])
def action_isolate() -> Any:
    """
    Mock endpoint: simulate isolating a host/network for a given incident.
    """
    data = request.get_json(force=True, silent=True) or {}
    incident_id = data.get("incident_id")
    if not incident_id or incident_id not in INCIDENTS:
        return jsonify({"error": "Unknown incident_id"}), 404

    incident = INCIDENTS[incident_id]
    incident["status"] = "isolated"
    incident["last_action"] = "isolate"
    incident["last_action_at"] = datetime.now(timezone.utc).isoformat()

    return jsonify({"ok": True, "incident": incident})


@app.route("/api/action/revoke", methods=["POST"])
def action_revoke() -> Any:
    """
    Mock endpoint: simulate revoking tokens/credentials for a given incident.
    """
    data = request.get_json(force=True, silent=True) or {}
    incident_id = data.get("incident_id")
    if not incident_id or incident_id not in INCIDENTS:
        return jsonify({"error": "Unknown incident_id"}), 404

    incident = INCIDENTS[incident_id]
    incident["status"] = "revoked"
    incident["last_action"] = "revoke"
    incident["last_action_at"] = datetime.now(timezone.utc).isoformat()

    return jsonify({"ok": True, "incident": incident})


@app.route("/api/action/honeypot", methods=["POST"])
def action_honeypot() -> Any:
    """
    Mock endpoint: simulate routing traffic to a honeypot/sandbox.
    """
    data = request.get_json(force=True, silent=True) or {}
    incident_id = data.get("incident_id")
    if not incident_id or incident_id not in INCIDENTS:
        return jsonify({"error": "Unknown incident_id"}), 404

    incident = INCIDENTS[incident_id]
    incident["status"] = "honeypot"
    incident["last_action"] = "honeypot"
    incident["last_action_at"] = datetime.now(timezone.utc).isoformat()

    return jsonify({"ok": True, "incident": incident})


@app.route("/api/contain/undo/<incident_id>", methods=["POST"])
def undo_containment(incident_id: str) -> Any:
    """
    Undo containment for a given incident (simulate reversing network isolation / revoke).
    """
    if incident_id not in INCIDENTS:
        return jsonify({"error": "Unknown incident_id"}), 404

    incident = INCIDENTS[incident_id]
    incident["status"] = "undo"
    incident["undo_at"] = datetime.now(timezone.utc).isoformat()

    return jsonify({"ok": True, "incident": incident})


@app.route("/api/state", methods=["GET"])
def state() -> Any:
    """
    Return current state for the dashboard:
    - incidents: list of recent incidents (most recent first)
    - totals: ROI saved and counts.
    """
    incidents_sorted = sorted(
        INCIDENTS.values(),
        key=lambda x: x.get("created_at", ""),
        reverse=True,
    )
    return jsonify(
        {
            "total_roi_saved": TOTAL_ROI_SAVED,
            "incident_count": len(INCIDENTS),
            "incidents": incidents_sorted,
        }
    )


if __name__ == "__main__":
    # Simple dev server; in production you'd use gunicorn/uwsgi etc.
    app.run(host="0.0.0.0", port=8000, debug=True)

