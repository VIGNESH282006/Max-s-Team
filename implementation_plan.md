# Upgrade Plan: Advanced Agentic Threat Detection

The provided PDF document specifies requirements for an "Intelligent Immune System" with strict evaluation criteria. Below is the plan to upgrade the existing codebase to meet and exceed these criteria.

## Proposed Changes

### 1. Robustness against Adversarial AI (Ensemble Detection)
#### [MODIFY] [train_model.py](file:///d:/Hackathon/train_model.py)
- Train an `IsolationForest` model alongside the current `RandomForestClassifier`.
- While RF is great for known anomaly types (stolen token, lateral), IF will catch completely "Zero-Day" or heavily obfuscated adversarial traffic by flagging pure out-of-distribution outliers.
- Save the `IsolationForest` model to `models/if_model.joblib`.

### 2. Predictive Threat Intelligence (OSINT Integration)
#### [MODIFY] [app.py](file:///d:/Hackathon/app.py)
- Introduce a simulated OSINT / Threat Intel feed. This module will carry a list of "known bad" subnets or scraped dark web IPs.
- During ingestion (`/api/ingest`), cross-reference the incoming `source_ip` and `dest_ip` with this threat intel list to flag predictive risks before the ML model even processes it, or boost the ML anomaly probability.

### 3. Explainable AI (XAI) with SHAP
#### [MODIFY] [app.py](file:///d:/Hackathon/app.py)
- Integrate the `shap` library (SHapley Additive exPlanations).
- For every detected anomaly, generate local SHAP values to explain *exactly* which features (e.g., `dest_port`, `bytes_sent`, `duration_sec`) contributed most to the anomaly score.
- Pass these top contributing features to Claude in [claude_reasoning.py](file:///d:/Hackathon/claude_reasoning.py) so the play-by-play narrative is explicitly backed by data science.

#### [MODIFY] [claude_reasoning.py](file:///d:/Hackathon/claude_reasoning.py)
- Accept `top_features` from the ML layer and explicitly include them in the prompt for the `interrogation_log` and `play_by_play_narrative`.

### 4. Adaptability & Learning (Continuous Training & Feedback)
#### [MODIFY] [app.py](file:///d:/Hackathon/app.py)
- Add a POST `/api/feedback` endpoint where analysts can flag an incident as a **False Positive** or **False Negative**.
- Save these corrections to a local `data/feedback.jsonl` file.

#### [NEW] [retrain_pipeline.py](file:///d:/Hackathon/retrain_pipeline.py)
- A new script that loads original logs AND `feedback.jsonl`, then retrains the models (RF and IF) and hot-swaps them. This directly fulfills the "Adaptability & Learning" criteria.

### 5. Advanced SOAR (Playbook Automation)
#### [MODIFY] [app.py](file:///d:/Hackathon/app.py)
- Instead of just mocking containment by mutating a dictionary state, the API will generate real mitigation scripts in a `playbooks/` folder (e.g., `block_10.0.1.5.bat` utilizing Windows firewall rules or iptables commands).

---
## Verification Plan

### Automated Tests
1. **Model Training**: Run `python train_model.py` to ensure both RF and IF train and save successfully.
2. **API Ingestion**: Send a cURL POST to `/api/ingest` with normal and anomalous traffic to verify standard response, SHAP values generation, and OSINT intel flags.
3. **Feedback Loop**: Send a cURL POST to `/api/feedback` to mark a false positive, verify `feedback.jsonl` logs the correction.
4. **Retraining**: Run `python retrain_pipeline.py` to verify the model accuracy updates based on feedback.

### Manual Verification
1. Open the dashboard (if running) and visually confirm that the new SHAP explainability variables are being rendered or utilized in the Claude narratives.
2. Verify the `playbooks/` directory for generated firewall/mitigation scripts.
