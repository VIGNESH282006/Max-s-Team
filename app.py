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
from osint import analyze_ioc, get_threat_intelligence


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
    out.setdefault("failed_login_attempts", 0)
    out.setdefault("request_frequency", 1)
    out.setdefault("user_privilege", "user")
    # SECURITY: always strip user-supplied attack_type — re-inferred later
    out["attack_type"] = None
    return out


SHAP_DISPLAY_NAME_MAP: Dict[str, str] = {
    "source_ip_reputation_score": "Source IP Reputation Score",
    "dest_port": "Destination Port",
    "protocol_type": "Protocol Type",
    "packet_size_payload_length": "Packet Size / Payload Length",
    "connection_duration": "Connection Duration",
    "failed_login_attempts": "Failed Login Attempts",
    "data_transfer_volume": "Data Transfer Volume",
    "user_privilege_level": "User Privilege Level",
    "geo_location_of_ip": "Geo-location of IP",
    "request_frequency": "Request Frequency",
}

SHAP_PRIORITY_FEATURES: List[str] = [
    "source_ip_reputation_score",
    "dest_port",
    "protocol_type",
    "packet_size_payload_length",
    "connection_duration",
    "failed_login_attempts",
    "data_transfer_volume",
    "user_privilege_level",
    "geo_location_of_ip",
    "request_frequency",
]


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
        feature_names = X.columns
        priority_indices = [
            idx for idx, name in enumerate(feature_names) if str(name) in SHAP_PRIORITY_FEATURES
        ]
        if priority_indices:
            top_indices = sorted(priority_indices, key=lambda idx: abs_sv[idx], reverse=True)[:10]
        else:
            top_indices = np.argsort(abs_sv)[::-1][:10]  # Fallback if schema drifts
        for i in top_indices:
            raw_name = str(feature_names[i])
            top_features.append({
                "feature": SHAP_DISPLAY_NAME_MAP.get(raw_name, raw_name),
                "raw_feature": raw_name,
                "value": float(X.iloc[0, i]),
                "impact": float(sv[i])
            })

    return {
        "prediction": pred,
        "probability": proba,
        "normalized_log": normalized,
        "top_features": top_features[:10],
        "model_signals": {
            "isolation_forest_outlier": if_pred == -1,
            "osint_known_bad_ip": is_osint,
        },
    }


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


@app.route("/login", methods=["GET"])
def login_page() -> Any:
    """Serve the SOC Analyst authentication page."""
    return render_template("login.html")


@app.route("/api/ingest", methods=["POST"])
def ingest() -> Any:
    """
    Receive a log event and run OSINT -> ML -> Claude pipeline.
    OSINT threat intelligence is cross-referenced BEFORE ML processing
    to catch known threats instantly (dark-web IPs, C2 servers, IOC feeds).
    Returns an incident object if anomalous, or a normal-response otherwise.
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    if not isinstance(payload, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    source_ip = payload.get("source_ip", "unknown") if isinstance(payload, dict) else "unknown"
    pipeline_started = time.perf_counter()
    
    # ===== STAGE 1: OSINT THREAT INTELLIGENCE LOOKUP =====
    # Cross-reference against dark-web IPs, C2 servers, IOC feeds BEFORE ML processing
    stage_osint_started = time.perf_counter()
    osint_result = analyze_ioc(payload)
    stage_osint_ms = (time.perf_counter() - stage_osint_started) * 1000
    is_osint_hit = osint_result.get("is_ioс", False)  # "Indicator of Compromise" flag
    
    if is_osint_hit:
        print(f"[OSINT HIT] Threat intelligence match: {osint_result.get('summary')}")
    
    # ===== STAGE 2: ML ANOMALY DETECTION =====
    stage_ml_started = time.perf_counter()
    ml_result = score_log_with_model(payload)
    stage_ml_ms = (time.perf_counter() - stage_ml_started) * 1000
    is_anomaly = ml_result["prediction"] == 1 or is_osint_hit  # Escalate if OSINT finds threat
    
    # If OSINT found IOC, boost ML probability to ensure incident is created
    if is_osint_hit and not is_anomaly:
        ml_result["probability"] = max(ml_result["probability"], 0.99)
        is_anomaly = True

    # ===== STAGE 3: ADVERSARIAL PROBE DETECTION =====
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
                "osint_result": osint_result,
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

    # Prepare top features with OSINT findings prioritized
    top_features = ml_result.get("top_features", [])
    
    # Prepend OSINT findings to top_features so Claude considers them prominently
    if osint_result.get("threats_found"):
        for threat in osint_result["threats_found"]:
            osint_feature = {
                "feature": f"OSINT_{threat.get('type', 'unknown').upper()}",
                "value": threat.get("indicator", ""),
                "impact": 0.99 if threat.get("severity") == "critical" else 0.85,
                "osint_source": threat.get("sources", []),
                "osint_category": threat.get("categories", []),
            }
            top_features.insert(0, osint_feature)

    stage_llm_started = time.perf_counter()
    llm_result = analyze_anomaly(anomaly_log, top_features=top_features)
    stage_llm_ms = (time.perf_counter() - stage_llm_started) * 1000

    stage_frontend_prepare_started = time.perf_counter()

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
        "threat_level": llm_result.get("threat_level", "High"),
        "attack_type_classification": llm_result.get("attack_type", "Unknown"),
        "key_shap_features": llm_result.get("key_shap_features", []),
        "llm_explanation": llm_result.get("explanation", ""),
        "recommended_soc_actions": llm_result.get("recommended_soc_actions", []),
        "play_by_play_narrative": llm_result["play_by_play_narrative"],
        "estimated_roi_saved": llm_result["estimated_roi_saved"],
        "generated_yara_rule": llm_result["generated_yara_rule"],
        "interrogation_log": llm_result["interrogation_log"],
        "status": "contained",
        "top_features": ml_result.get("top_features", []),
        "model_signals": ml_result.get("model_signals", {}),
        "osint_findings": osint_result.get("threats_found", []),
        "osint_severity": osint_result.get("severity", "clean"),
        "osint_is_ioc": osint_result.get("is_ioс", False),
        "osint_summary": osint_result.get("summary", ""),
    }
    stage_frontend_prepare_ms = (time.perf_counter() - stage_frontend_prepare_started) * 1000
    incident["pipeline_timing_ms"] = {
        "data_fetch_osint": round(stage_osint_ms, 2),
        "ml_load_train_reason": round(stage_ml_ms, 2),
        "llm_claude_reasoning": round(stage_llm_ms, 2),
        "frontend_prepare": round(stage_frontend_prepare_ms, 2),
    }
    incident["pipeline_total_ms"] = round((time.perf_counter() - pipeline_started) * 1000, 2)

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
        Allow SOC analysts to label incidents for retraining.

        Supported payloads:
        - Legacy correction field:
            correction = "false_positive" | "false_negative"
        - New direct analyst label:
            analyst_label = "anomaly" | "normal"

    Saves to data/feedback.jsonl for retraining.
    """
    data = request.get_json(force=True, silent=True) or {}
    incident_id = data.get("incident_id")
    correction = data.get("correction")
    analyst_label = (data.get("analyst_label") or "").strip().lower()

    if not incident_id or incident_id not in INCIDENTS:
        return jsonify({"error": "Unknown incident_id"}), 404

    incident = INCIDENTS[incident_id]
    log_data = dict(incident["log"])

    final_label = None
    # New mode: direct SOC analyst label
    if analyst_label in ("anomaly", "normal"):
        final_label = 1 if analyst_label == "anomaly" else 0
    # Backward compatible mode
    elif correction == "false_positive":
        final_label = 0
    elif correction == "false_negative":
        final_label = 1
    else:
        return jsonify({
            "error": "Provide analyst_label ('anomaly'|'normal') or correction ('false_positive'|'false_negative')."
        }), 400

    log_data["is_anomaly"] = final_label
    log_data["feedback_source_incident_id"] = incident_id
    log_data["feedback_timestamp"] = datetime.now(timezone.utc).isoformat()
        
    feedback_file = BASE_DIR / "data" / "feedback.jsonl"
    feedback_file.parent.mkdir(parents=True, exist_ok=True)
    with open(feedback_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_data) + "\n")

    incident["status"] = "feedback_logged"
    incident["analyst_label"] = "anomaly" if final_label == 1 else "normal"
    incident["feedback_logged_at"] = datetime.now(timezone.utc).isoformat()
    return jsonify({
        "ok": True,
        "message": "Feedback recorded for retraining",
        "incident_id": incident_id,
        "analyst_label": incident["analyst_label"],
    })


@app.route("/api/retraining_queue", methods=["GET"])
def retraining_queue() -> Any:
    """
    Return analyst-labeled records queued for retraining.

    Reads data/feedback.jsonl and returns:
    - total_labeled
    - anomaly_labels
    - normal_labels
    - recent_items (most recent first)
    """
    feedback_file = BASE_DIR / "data" / "feedback.jsonl"
    rows: List[Dict[str, Any]] = []

    if feedback_file.exists():
        with open(feedback_file, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    rows.append(json.loads(raw))
                except json.JSONDecodeError:
                    # Skip malformed lines instead of failing the endpoint
                    continue

    total_labeled = len(rows)
    anomaly_labels = sum(1 for r in rows if int(r.get("is_anomaly", 0) or 0) == 1)
    normal_labels = total_labeled - anomaly_labels

    # Most recent first, capped for UI performance
    recent_rows = sorted(
        rows,
        key=lambda r: r.get("feedback_timestamp") or r.get("timestamp") or "",
        reverse=True,
    )[:50]

    recent_items = []
    for r in recent_rows:
        recent_items.append(
            {
                "incident_id": r.get("feedback_source_incident_id") or "unknown",
                "label": "anomaly" if int(r.get("is_anomaly", 0) or 0) == 1 else "normal",
                "feedback_timestamp": r.get("feedback_timestamp"),
                "attack_type": r.get("attack_type"),
                "source_ip": r.get("source_ip"),
                "dest_ip": r.get("dest_ip"),
            }
        )

    return jsonify(
        {
            "total_labeled": total_labeled,
            "anomaly_labels": anomaly_labels,
            "normal_labels": normal_labels,
            "recent_items": recent_items,
        }
    )

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
    count = len(INCIDENTS)
    if count == 0:
        threat = "Low"
    elif count <= 2:
        threat = "Medium"
    elif count <= 5:
        threat = "High"
    else:
        threat = "Critical"
    return jsonify(
        {
            "total_roi_saved": TOTAL_ROI_SAVED,
            "incident_count": count,
            "threat_level": threat,
            "incidents": incidents_sorted,
        }
    )


@app.route("/api/reset", methods=["POST"])
def reset_state() -> Any:
    """Clear all in-memory incident state. Useful between demo runs."""
    global TOTAL_ROI_SAVED, _INCIDENT_COUNTER
    INCIDENTS.clear()
    TOTAL_ROI_SAVED = 0.0
    _INCIDENT_COUNTER = 0
    # Clear the retraining feedback file
    feedback_file = BASE_DIR / "data" / "feedback.jsonl"
    if feedback_file.exists():
        feedback_file.write_text("")
    return jsonify({"status": "ok", "message": "State cleared."})


if __name__ == "__main__":
    # Simple dev server; in production you'd use gunicorn/uwsgi etc.
    app.run(host="0.0.0.0", port=8000, debug=True)

