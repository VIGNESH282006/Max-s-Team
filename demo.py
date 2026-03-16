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


API_INGEST_URL = "http://127.0.0.1:8000/api/ingest"
LOG_PATH = Path("data/synthetic_logs.jsonl")

# How many events to send in the demo (None = all)
MAX_EVENTS: int | None = 400

# Delay between events in seconds (tune for your demo)
SLEEP_BETWEEN_EVENTS = 0.05  # 50ms


def iter_logs(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def main() -> None:
    if not LOG_PATH.exists():
        raise SystemExit(
            f"Log file not found at {LOG_PATH}. Run `python log_generator.py` first."
        )

    print("=== Agentic SOC Demo ===")
    print(f"Streaming events from {LOG_PATH} to {API_INGEST_URL}")
    print("Press Ctrl+C to stop.\n")

    sent = 0
    anomalies = 0

    for log in iter_logs(LOG_PATH):
        if MAX_EVENTS is not None and sent >= MAX_EVENTS:
            break

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
                f"total_roi_saved=${roi:,.0f}"
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

