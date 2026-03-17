"""
The Agentic SOC - Phase 5: Simulation Runner

Streams synthetic SIEM logs into the Flask API to drive the full
<5s detect → reason → contain pipeline for the demo.

Usage:
  1. Ensure the backend is running:
       python app.py
  2. In another terminal:
       python demo.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable

import requests


import random
from datetime import datetime, timedelta

from log_generator import _base_log, _emit, _random_internal_ip, _random_external_ip

API_INGEST_URL = "http://127.0.0.1:8000/api/ingest"

# Delay between events in seconds (tune for your demo)
SLEEP_BETWEEN_EVENTS = 4.0  # Stream 1 event every 4 seconds


def live_log_stream() -> Iterable[dict]:
    """Generates an infinite stream of fresh logs independent of the training data."""
    random.seed()  # Ensure fresh randomness (don't use the training seed)
    ts = datetime.utcnow()

    # Create persistent attackers for the session so that lateral movement looks connected
    lateral_patient_zero = _random_internal_ip()
    lateral_victims = [_random_internal_ip() for _ in range(5)]
    
    last_anomaly_time = 0

    while True:
        ts += timedelta(seconds=random.uniform(0.1, 2.0))
        
        # 85% normal, 7% stolen token, 8% lateral movement
        choice = random.random()
        
        # Rate limit anomalies to max 1 per 4.5 seconds real-time
        now = time.time()
        if choice >= 0.85 and (now - last_anomaly_time) < 4.5:
            choice = 0.5  # Force normal
        
        if choice < 0.85:
            # Normal log
            log = _base_log(ts)
            _emit(log)
        elif choice < 0.92:
            # Stolen token
            last_anomaly_time = now
            log = _base_log(ts)
            log["is_anomaly"] = 1
            log["attack_type"] = "stolen_token"
            log["source_ip"] = _random_external_ip() if random.random() < 0.7 else _random_internal_ip()
            log["dest_ip"] = _random_internal_ip()
            log["action"] = random.choice(["auth", "login", "token_validate"])
            log["dest_port"] = random.choice([443, 8443, 8080])
            log["protocol"] = random.choice(["HTTPS", "HTTP"])
            _emit(log)
            if log.get("dest_port") == 0:
                log["dest_port"] = 443
        else:
            # Lateral movement
            last_anomaly_time = now
            log = _base_log(ts)
            log["is_anomaly"] = 1
            log["attack_type"] = "lateral_movement"
            log["source_ip"] = lateral_patient_zero
            log["dest_ip"] = random.choice(lateral_victims) if lateral_victims else _random_internal_ip()
            log["protocol"] = random.choice(["SMB", "RDP", "SSH", "LDAP"])
            log["dest_port"] = {"SMB": 445, "RDP": 3389, "SSH": 22, "LDAP": 389}.get(log["protocol"], 445)
            log["action"] = "connection"
            _emit(log)
            
        yield log


def main() -> None:
    print("=== Agentic SOC Demo ===")
    print(f"Streaming live generated events to {API_INGEST_URL}")
    print("Press Ctrl+C to stop.\n")

    # Reset backend state for a clean demo
    try:
        requests.post("http://127.0.0.1:8000/api/reset", timeout=3)
        print("[RESET] Backend state cleared for fresh demo.\n")
    except Exception:
        print("[WARN] Could not reset backend state.\n")

    sent = 0
    anomalies = 0

    # No MAX_EVENTS limit by default, runs infinitely
    for log in live_log_stream():
        sent += 1
        t0 = time.perf_counter()
        try:
            resp = requests.post(API_INGEST_URL, json=log, timeout=4)
        except Exception as exc:
            print(f"[{sent:05d}] ERROR sending event: {exc}")
            time.sleep(SLEEP_BETWEEN_EVENTS)
            continue

        latency_ms = (time.perf_counter() - t0) * 1000

        if not resp.ok:
            print(f"[{sent:05d}] API {resp.status_code}: {resp.text[:200]}")
            time.sleep(SLEEP_BETWEEN_EVENTS)
            continue

        body = resp.json()
        status = body.get("status")

        if status == "anomaly":
            anomalies += 1
            incident = body.get("incident", {})
            incident_id = incident.get("incident_id", "?")
            action = incident.get("containment_action", "?")
            roi = body.get("total_roi_saved", 0)
            narrative = (incident.get("play_by_play_narrative") or "").strip()

            print(
                f"[{sent:05d}] ANOMALY {incident_id} "
                f"action={action} "
                f"latency={latency_ms:.1f}ms "
                f"total_roi_saved=₹{roi:,.0f}"
            )
            if narrative:
                print(f"         {narrative}")
        else:
            # For normal events, keep output light
            print(
                f"[{sent:05d}] normal "
                f"p_anom={body.get('ml_probability', 0):.3f} "
                f"latency={latency_ms:.1f}ms",
                end="\r",
            )

        time.sleep(SLEEP_BETWEEN_EVENTS)

    print("\n\n=== Demo complete ===")
    print(f"Events sent:     {sent}")
    print(f"Anomalies seen:  {anomalies}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")

