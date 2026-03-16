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
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
import shap
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template

from claude_reasoning import analyze_anomaly
from train_model import build_features


BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "anomaly_rf_model.joblib"
ENCODERS_PATH = MODELS_DIR / "encoders.joblib"
PLAYBOOKS_DIR = BASE_DIR / "playbooks"
PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)


load_dotenv(override=False)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Model loading and feature pipeline
# ---------------------------------------------------------------------------
clf = joblib.load(MODEL_PATH)
IF_MODEL_PATH = MODELS_DIR / "anomaly_if_model.joblib"
if_clf = joblib.load(IF_MODEL_PATH) if IF_MODEL_PATH.exists() else None

encoders_meta: Dict[str, Any] = joblib.load(ENCODERS_PATH)
FEATURE_COLUMNS: List[str] = encoders_meta.get("feature_columns", [])

# Initialize SHAP explainer
explainer = shap.TreeExplainer(clf)

OSINT_KNOWN_BAD_IPS = {"203.0.113.50", "198.51.100.23", "185.199.108.153", "104.28.14.74", "45.33.32.156"}


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------
_SAFE_IP_RE = re.compile(r"^[0-9a-zA-Z.:\-]{1,50}$")
_SAFE_USER_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _sanitize_ip(ip: str) -> str:
    """Allow only IPv4/IPv6 safe characters; reject anything else."""
    if not isinstance(ip, str):
        return "unknown"
    cleaned = re.sub(r"[^0-9a-zA-Z.:\-]", "_", ip)[:50]
    return cleaned if cleaned else "unknown"


def _sanitize_user(user: str) -> str:
    """Allow only alphanumeric, underscore, and dash characters."""
    if not isinstance(user, str):
        return "unknown"
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "_", user)[:64]
    return cleaned if cleaned else "unknown"


# ---------------------------------------------------------------------------
# Adversarial probe detection state
# ---------------------------------------------------------------------------
# Tracks per-source-IP request timestamps within a sliding window
_ip_request_times: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
# Tracks recent events whose ML score was near the 0.5 decision boundary
_borderline_scores: deque = deque(maxlen=500)

_PROBE_WINDOW_SEC = 60        # sliding window length in seconds
_PROBE_RATE_LIMIT = 20        # requests per window before flagging
_PROBE_BOUNDARY_MIN = 5       # min borderline events from same IP to flag
_PROBE_BOUNDARY_LOW = 0.35    # lower edge of "near decision boundary"
_PROBE_BOUNDARY_HIGH = 0.65   # upper edge of "near decision boundary"


def _check_probe_attack(source_ip: str, probability: float) -> Dict[str, Any]:
    """
    Detect adversarial probing patterns:
      1. Rate limit: same IP sends > _PROBE_RATE_LIMIT requests per minute.
      2. Boundary probing: many requests from same IP cluster near the 0.5
         decision threshold, which suggests iterative evasion testing.
    """
    now = time.time()
    times = _ip_request_times[source_ip]
    times.append(now)

    recent_count = sum(1 for t in times if now - t <= _PROBE_WINDOW_SEC)

    if _PROBE_BOUNDARY_LOW <= probability <= _PROBE_BOUNDARY_HIGH:
        _borderline_scores.append({"ip": source_ip, "time": now, "prob": probability})

    borderline_count = sum(
        1 for s in _borderline_scores
        if s["ip"] == source_ip and now - s["time"] <= _PROBE_WINDOW_SEC
    )

    alerts: List[str] = []
    if recent_count > _PROBE_RATE_LIMIT:
        alerts.append(
            f"Rate-limit exceeded: {recent_count} requests from {source_ip} "
            f"in the last {_PROBE_WINDOW_SEC}s (limit {_PROBE_RATE_LIMIT})"
        )
    if borderline_count >= _PROBE_BOUNDARY_MIN:
        alerts.append(
            f"Decision-boundary probing detected: {borderline_count} near-threshold "
            f"events from {source_ip} in the last {_PROBE_WINDOW_SEC}s"
        )

    return {
        "is_probe": bool(alerts),
        "alerts": alerts,
        "request_rate": recent_count,
        "borderline_count": borderline_count,
    }


def _ensure_log_defaults(log: Dict[str, Any]) -> Dict[str, Any]:
    """Fill in missing keys with safe defaults so build_features works.

    SECURITY: attack_type is NEVER propagated from the raw inbound payload —
    it could be used to steer the LLM containment decision (prompt injection).
    It is always re-inferred from ML-observed fields after scoring.
    """
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
    # SECURITY: always strip user-supplied attack_type — re-inferred later
    out["attack_type"] = None
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
    
    is_osint = normalized.get("source_ip") in OSINT_KNOWN_BAD_IPS or normalized.get("dest_ip") in OSINT_KNOWN_BAD_IPS
    
    proba = float(clf.predict_proba(X)[0][1])
    pred = int(proba >= 0.5)

    if_pred = 1
    if if_clf:
        if_pred = int(if_clf.predict(X)[0])
        if if_pred == -1:
            pred = 1
            proba = max(proba, 0.85)
            
    if is_osint:
        pred = 1
        proba = max(proba, 0.99)

    top_features = []
    if pred == 1:
        # Calculate SHAP values for the anomaly class
        shap_values = explainer.shap_values(X)
        # shap_values[1] is for the anomaly class (index 1) in RandomForest
        if isinstance(shap_values, list):
            sv = shap_values[1][0]
        else:
            sv = shap_values[0] # Depending on shap version, it might return a single array for binary or multi-class array
            if len(sv.shape) > 1:
               sv = sv[:, 1] if sv.shape[1] > 1 else sv
            
        abs_sv = np.abs(sv)
        top_indices = np.argsort(abs_sv)[::-1][:3] # Top 3 features
        feature_names = X.columns
        for i in top_indices:
            top_features.append({
                "feature": str(feature_names[i]),
                "value": float(X.iloc[0, i]),
                "impact": float(sv[i])
            })
            
        if is_osint:
            top_features.insert(0, {"feature": "OSINT_Intel", "value": "Known Bad IP", "impact": 1.0})
        if if_pred == -1:
            top_features.insert(0, {"feature": "Ensemble_ZeroDay_Detector", "value": "Outlier", "impact": 0.95})

    return {"prediction": pred, "probability": proba, "normalized_log": normalized, "top_features": top_features[:4]}


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


def generate_playbook(incident: dict):
    """Automatically generate an executable mitigation script in the playbooks/ directory.

    SECURITY: IP addresses and user IDs are sanitized before being embedded in
    shell/PowerShell scripts to prevent command injection.
    """
    action = incident.get("containment_action")
    # Sanitize all values that will be written into executable scripts
    ip = _sanitize_ip(incident["log"].get("source_ip", "unknown"))
    user = _sanitize_user(incident["log"].get("user_id", "unknown"))
    inc_id = _sanitize_user(incident.get("incident_id", "INC-00000"))

    if action == "isolate":
        script_name = f"{inc_id}_isolate_{ip}.bat"
        content = (
            f"@echo off\n"
            f":: Autoblocked by Agentic SOC\n"
            f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in action=block remoteip={ip}\n"
            f"netsh advfirewall firewall add rule name=\"Block_{ip}_out\" dir=out action=block remoteip={ip}\n"
            f"echo Isolated {ip}\n"
        )
    elif action == "revoke":
        script_name = f"{inc_id}_revoke_{user}.ps1"
        content = (
            f"# Revoke script by Agentic SOC\n"
            f"# Simulated Azure AD/Okta revocation\n"
            f"Write-Host 'Revoking sessions for {user}...'\n"
            f"# Revoke-AzureADUserAllRefreshToken -ObjectId '{user}'\n"
            f"Write-Host 'Revoked!'\n"
        )
    elif action == "honeypot":
        script_name = f"{inc_id}_route_honeypot_{ip}.sh"
        content = (
            f"#!/bin/bash\n"
            f"# Route {ip} to honeypot (Agentic SOC)\n"
            f"iptables -t nat -A PREROUTING -s '{ip}' -j DNAT --to-destination 10.0.99.99\n"
        )
    else:
        return

    try:
        path = PLAYBOOKS_DIR / script_name
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        print(f"Error generating playbook: {e}")


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

    source_ip = payload.get("source_ip", "unknown") if isinstance(payload, dict) else "unknown"
    ml_result = score_log_with_model(payload)
    is_anomaly = ml_result["prediction"] == 1

    # --- Adversarial probe detection (runs on every request, anomaly or not) ---
    probe_info = _check_probe_attack(str(source_ip), ml_result["probability"])
    if probe_info["is_probe"]:
        # Log to console; in production send to SIEM/alerting
        print(f"[PROBE ALERT] {probe_info['alerts']}")

    if not is_anomaly:
        return jsonify(
            {
                "status": "normal",
                "ml_prediction": 0,
                "ml_probability": ml_result["probability"],
                "message": "Event scored as normal traffic.",
                "probe_detection": probe_info,
            }
        )

    anomaly_log = ml_result["normalized_log"]

    # SECURITY: attack_type was already stripped in _ensure_log_defaults.
    # Re-infer it here from ML-observed fields only — never from user-supplied data.
    proto = anomaly_log.get("protocol", "")
    action_field = anomaly_log.get("action", "")
    dest_port = int(anomaly_log.get("dest_port") or 0)
    if proto in ("SMB", "RDP", "SSH", "LDAP") or dest_port in (445, 3389, 22, 389):
        anomaly_log["attack_type"] = "lateral_movement"
    elif action_field in ("auth", "login", "token_validate"):
        anomaly_log["attack_type"] = "stolen_token"
    else:
        anomaly_log["attack_type"] = "unknown_anomaly"

    llm_result = analyze_anomaly(anomaly_log, top_features=ml_result.get("top_features", []))

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
        "top_features": ml_result.get("top_features", []),
    }
    INCIDENTS[incident_id] = incident

    # Generate the playbook script
    generate_playbook(incident)

    return jsonify(
        {
            "status": "anomaly",
            "incident": incident,
            "total_roi_saved": TOTAL_ROI_SAVED,
            "probe_detection": probe_info,
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


@app.route("/api/feedback", methods=["POST"])
def submit_feedback() -> Any:
    """
    Allow SOC analysts to flag an incident as a false positive or missed anomaly.
    Saves to data/feedback.jsonl for retraining.
    """
    data = request.get_json(force=True, silent=True) or {}
    incident_id = data.get("incident_id")
    correction = data.get("correction") # 'false_positive' or 'false_negative'

    if not incident_id or incident_id not in INCIDENTS:
        return jsonify({"error": "Unknown incident_id"}), 404

    incident = INCIDENTS[incident_id]
    log_data = incident["log"]
    
    # Correct the label
    if correction == "false_positive":
        log_data["is_anomaly"] = 0
    elif correction == "false_negative":
        log_data["is_anomaly"] = 1
        
    feedback_file = BASE_DIR / "data" / "feedback.jsonl"
    feedback_file.parent.mkdir(parents=True, exist_ok=True)
    with open(feedback_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_data) + "\n")

    incident["status"] = "feedback_logged"
    return jsonify({"ok": True, "message": "Feedback recorded for retraining"})

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

