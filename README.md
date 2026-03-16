# The Agentic SOC – Autonomous L1 Analyst (CYBERSHIELD 2026)

> **Goal:** Turn hours-long human triage into a **\<5s autonomous detect → reason → contain** pipeline for a Level 1 SOC analyst.

This project is your CYBERSHIELD 2026 hackathon entry: **“The Agentic SOC”** – an agentic system that:

- Generates realistic SIEM-style logs.
- Detects anomalies with an ML model (RandomForest).
- Hands flagged events to an LLM (Claude) for rich reasoning + containment recommendations.
- Exposes a Flask API for ingestion and auto-containment.
- Visualizes incidents on a **live SOC dashboard** (lightweight HTML/JS/CSS).
- Streams a **simulation runner** to show the full pipeline in real time.

The architecture is intentionally simple, end-to-end, and demo‑ready.

---

## 1. High‑Level Architecture

### Data → ML → LLM → Actions → UI

1. **Synthetic Log Generator (`log_generator.py`)**
   - Creates realistic network/auth logs with both **normal traffic** and **simulated attacks**:
     - `stolen_token` – credential reuse from suspicious IPs / impossible travel.
     - `lateral_movement` – internal scanning via SMB/RDP/SSH.
   - Outputs a JSONL file: `data/synthetic_logs.jsonl` (one JSON log per line).

2. **Anomaly Detection (`train_model.py` + `models/…`)**
   - Trains a **RandomForestClassifier** on the synthetic logs.
   - Saves:
     - `models/anomaly_rf_model.joblib` – the trained model.
     - `models/encoders.joblib` – feature column ordering + categorical mappings.
   - At runtime, the Flask app reuses the same **feature pipeline** for scoring incoming logs.

3. **LLM Reasoning (`claude_reasoning.py`)**
   - Takes any event the ML model flags as an anomaly.
   - Calls **Anthropic Claude** (Messages API) with a tightly constrained prompt.
   - Returns a strict JSON object with:
     - `containment_action`: `"isolate" | "revoke" | "honeypot"`
     - `play_by_play_narrative`: human‑readable Slack-style commentary.
     - `estimated_roi_saved`: estimated dollars saved (targeting a \$4.8M breach baseline).
     - `generated_yara_rule`: custom YARA rule text derived from the event.
     - `interrogation_log`: stepwise explanation of the decision.
   - If the API key is missing or the call fails, falls back to a **safe default response**.

4. **Backend API (`app.py`)**
   - Flask app exposing:
     - `POST /api/ingest` – ingest a log, run **ML → (optional) Claude**, and create an incident if anomalous.
     - `POST /api/action/{isolate|revoke|honeypot}` – mock action endpoints to “execute” containment for an incident.
     - `POST /api/contain/undo/<incident_id>` – undo a containment (for false positives / operator override).
     - `GET /api/state` – current system state for the frontend: incidents list, total ROI, etc.
     - `GET /` – serves the dashboard UI (`templates/index.html`).
   - Maintains **in-memory state**:
     - `INCIDENTS` – dict of `incident_id → incident`.
     - `TOTAL_ROI_SAVED` – running total of ROI from containment decisions.

5. **Frontend Dashboard (`templates/index.html`, `static/style.css`, `static/dashboard.js`)**
   - Pure **HTML + CSS + vanilla JS**, no heavy frameworks.
   - **Light theme** UI with three main sections:
     - **Patient Zero Graph** – 5-node vis-network graph showing the compromised node and peers.
       - Healthy: Patient Zero node is **blue** with no box.
       - Anomaly: Patient Zero node turns **red**, and a **grey containment box** appears on `isolate`/`revoke`.
       - When an incident is undone, the graph returns to the healthy state.
     - **Live Feed** – scrolling log of incidents:
       - Clear, structured text:  
         `HH:MM:SS | Incident INC-00008 | Attack: lateral_movement | Containment: isolate`
       - Followed by Claude’s `play_by_play_narrative`.
     - **SOC Panel** –
       - Shows the **latest YARA rule** (`generated_yara_rule`).
       - Contains **UNDO CONTAINMENT** button bound to `/api/contain/undo/<incident_id>`.
   - Polls `GET /api/state` every 2s to stay in sync with the backend.

6. **Simulation Runner (`demo.py`)**
   - Streams events from `data/synthetic_logs.jsonl` into `POST /api/ingest`:
     - Default: `MAX_EVENTS = 400`, `SLEEP_BETWEEN_EVENTS = 0.05` (50 ms).
   - Logs to the console:
     - For **anomaly**: incident id, containment action, latency, and cumulative ROI.
     - For **normal**: lightweight progress line with anomaly probability and latency.
   - Drives the full E2E demo (backend + frontend) in real time.

---

## 2. Tech Stack

- **Language:** Python 3.10+
- **ML:** `scikit-learn` (RandomForestClassifier), `numpy`, `pandas`, `joblib`
- **LLM:** Anthropic Claude – Python SDK (`anthropic`), Messages API
- **Backend:** Flask
- **Frontend:** HTML, CSS, vanilla JS, [vis-network](https://visjs.github.io/vis-network/) via CDN
- **Simulation:** `requests` (for posting logs to the Flask API)

---

## 3. Setup & Installation

### 3.1. Clone and environment

```bash
git clone https://github.com/VIGNESH282006/Max-s-Team.git
cd Max-s-Team

# (Recommended) Create a virtualenv
python -m venv .venv
.\.venv\Scripts\activate  # Windows PowerShell
# source .venv/bin/activate  # macOS/Linux

pip install -r requirements.txt
```

### 3.2. Anthropic API key

Create a `.env` file in the project root (already present in dev, but **never commit a real key** to public repos):

```env
ANTHROPIC_API_KEY="sk-ant-..."
```

The project uses `python-dotenv` (via `load_dotenv()` in `claude_reasoning.py` and `app.py`) to load this automatically at runtime. If the key is missing or invalid, the system gracefully falls back to a default reasoning path so the demo still runs.

> **Security note:** In a real deployment, you should **not** commit `.env` and should store secrets in a secure secrets manager. For the hackathon, ensure the public repo does not contain a live key.

### 3.3. Generate synthetic logs

```bash
python log_generator.py
```

This creates:

- `data/synthetic_logs.jsonl` (~9.5k events)
  - Mix of normal + `stolen_token` + `lateral_movement` events.

### 3.4. Train the anomaly model

```bash
python train_model.py
```

This will:

- Train a **RandomForestClassifier** on the synthetic data.
- Print a classification report and confusion matrix.
- Save:
  - `models/anomaly_rf_model.joblib`
  - `models/encoders.joblib`

---

## 4. Running the System

### 4.1. Start the backend (Flask API)

```bash
python app.py
```

By default the app runs on:

- `http://127.0.0.1:8000/` – dashboard UI
- API endpoints under `http://127.0.0.1:8000/api/...`

### 4.2. Start the simulation runner

In a separate terminal:

```bash
python demo.py
```

You should see console output like:

```text
=== Agentic SOC Demo ===
Streaming events from data/synthetic_logs.jsonl to http://127.0.0.1:8000/api/ingest
Press Ctrl+C to stop.

[00025] ANOMALY INC-00001 action=isolate latency=42.7ms total_roi_saved=$1,200,000
         [Auto] Anomaly detected: lateral_movement. Source 10.0.1.50 -> 10.0.2.100...
...
=== Demo complete ===
Events sent:     400
Anomalies seen:  37
```

### 4.3. View the dashboard

Open:

```text
http://127.0.0.1:8000/
```

You’ll see:

- **Patient Zero Graph:** 5 nodes (Patient Zero, DB, App, HR, Finance).
  - Healthy: Patient Zero is blue (core group).
  - Anomaly: Patient Zero turns red, containment box visible when `containment_action` is `isolate`/`revoke`.
- **Live Feed:** keeps prepending the latest anomalies with clear text.
- **SOC Panel:** shows latest YARA rule from the LLM and control buttons.

---

## 5. API Endpoints

All endpoints are served from the Flask app (`app.py`).

### 5.1. `POST /api/ingest`

Ingest a single log event. Example body:

```json
{
  "timestamp": "2025-03-15T12:00:00Z",
  "source_ip": "203.0.113.50",
  "dest_ip": "10.0.1.10",
  "src_port": 51515,
  "dest_port": 443,
  "protocol": "HTTPS",
  "user_id": "user_0042",
  "asset_id": "host-app1",
  "action": "token_validate",
  "outcome": "success",
  "bytes_sent": 1024,
  "duration_sec": 0.2,
  "attack_type": "stolen_token"
}
```

**Responses:**

- **Normal event**:

```json
{
  "status": "normal",
  "ml_prediction": 0,
  "ml_probability": 0.03,
  "message": "Event scored as normal traffic."
}
```

- **Anomalous event**:

```json
{
  "status": "anomaly",
  "incident": {
    "incident_id": "INC-00012",
    "created_at": "...",
    "log": { ...original/normalized log... },
    "ml_prediction": 1,
    "ml_probability": 0.97,
    "containment_action": "revoke",
    "play_by_play_narrative": "...",
    "estimated_roi_saved": 1200000,
    "generated_yara_rule": "rule ...",
    "interrogation_log": ["...", "..."],
    "status": "contained"
  },
  "total_roi_saved": 3600000.0
}
```

### 5.2. `POST /api/action/isolate` / `/revoke` / `/honeypot`

Mock endpoints representing auto‑containment actions.

**Body:**

```json
{ "incident_id": "INC-00012" }
```

**Response:**

```json
{
  "ok": true,
  "incident": {
    "incident_id": "INC-00012",
    "status": "isolated",
    "last_action": "isolate",
    "last_action_at": "..."
  }
}
```

### 5.3. `POST /api/contain/undo/<incident_id>`

Undo containment for a given incident (simulated rollback).

```http
POST /api/contain/undo/INC-00012
```

**Response:**

```json
{
  "ok": true,
  "incident": {
    "incident_id": "INC-00012",
    "status": "undo",
    "undo_at": "..."
  }
}
```

The frontend detects `status: "undo"` on the latest incident and:

- Returns the Patient Zero node to its **healthy** state.
+- Hides the containment box overlay.

### 5.4. `GET /api/state`

Returns the current state for the dashboard:

```json
{
  "total_roi_saved": 3600000.0,
  "incident_count": 8,
  "incidents": [
    {
      "incident_id": "INC-00012",
      "created_at": "...",
      "status": "contained",
      "ml_probability": 0.97,
      "containment_action": "revoke",
      "play_by_play_narrative": "..."
    },
    ...
  ]
}
```

---

## 6. How the ML & LLM Work Together

1. **ML (RandomForest)** handles **fast anomaly detection**:
   - Features include:
     - Internal vs external IP flags.
     - Ports, bytes, duration.
     - High‑risk ports (22, 445, 3389, etc.).
     - Encoded protocol / action / outcome fields.
   - `score_log_with_model()` in `app.py` converts a raw event into the same feature space as training.

2. **LLM (Claude)** handles **contextual reasoning**:
   - Receives the flagged SIEM event as a compact JSON context.
   - System prompt enforces JSON‑only output with the required keys.
   - Chooses between:
     - `"isolate"` – host/network isolation (e.g., lateral movement).
     - `"revoke"` – token/session revocation (e.g., stolen token).
     - `"honeypot"` – redirect to sandbox for observation.
   - Builds:
     - Plain‑English narrative.
     - Custom YARA rule.
     - A short interrogation log explaining the decision.

This separation mirrors a real SOC stack: **statistical detection** up front, **semantic reasoning** on top.

---

## 7. Demo Script (Suggested Flow)

1. **Scene setting (30–60 sec)**  
   Explain the breach cost baseline (~\$4.8M) and the goal: **sub‑5s autonomous L1 response**.

2. **Show the dashboard (patient zero graph + metrics).**

3. **Start `demo.py`** and narrate what happens:
   - Normal events stream by silently.
   - When an anomaly hits:
     - Graph: Patient Zero turns red, containment box appears.
     - Live Feed: new structured line appears with attack + containment.
     - SOC Panel: auto‑generated YARA rule appears.
     - Metrics: incident count increments; ROI saved ticks upward.

4. **Click UNDO CONTAINMENT** for a recent incident:
   - Show that the system supports **human‑in‑the‑loop overrides**.
   - Graph returns to healthy state; status text confirms the undo.

5. **Wrap with metrics:**  
   Mention model accuracy and anomaly precision (from `train_model.py` output) and discuss how this prototype could plug into a real SIEM / EDR environment.

---

## 8. Future Work / Extensions

- Swap synthetic logs for real SIEM/EDR data via connectors (e.g., Splunk, Elastic, Sentinel).
- Add authentication + RBAC for SOC operators on the UI.
- Persist incidents and actions in a database (e.g., Postgres) instead of in‑memory.
- Add streaming / websockets for lower‑latency UI updates.
- Expand the graph to show **multi-hop lateral movement** and multiple “patient zero” nodes.
- Integrate an outbound notification channel (e.g., Slack, email) powered by `play_by_play_narrative`.

---

## 9. Repository Layout

```text
.
├─ app.py                 # Flask backend (ML scoring, incidents, API + UI)
├─ claude_reasoning.py    # Claude integration + structured JSON reasoning
├─ demo.py                # Phase 5: simulation runner (streams logs into /api/ingest)
├─ log_generator.py       # Phase 1: synthetic SIEM log generator
├─ train_model.py         # Phase 1: RandomForest training + feature pipeline
├─ data/
│  └─ synthetic_logs.jsonl
├─ models/
│  ├─ anomaly_rf_model.joblib
│  └─ encoders.joblib
├─ static/
│  ├─ style.css           # Light theme + dashboard layout
│  └─ dashboard.js        # Graph, polling, live feed, UNDO controls
├─ templates/
│  └─ index.html          # Frontend markup
├─ requirements.txt
└─ .env                   # Anthropic API key (not for production)
```

This README should give judges and collaborators a complete mental model of **what The Agentic SOC does**, how it’s wired, and how to run the full demo end‑to‑end.

