"""
The Agentic SOC - Phase 2: The Agentic Brain (Claude API)
Takes an ML-flagged anomaly and uses Claude to produce:
- containment_action, play_by_play_narrative, estimated_roi_saved,
  generated_yara_rule, interrogation_log.
"""

import json
import os
import re
from typing import Any

from dotenv import load_dotenv

# Optional: only needed when calling the API
try:
    import anthropic
except ImportError:
    anthropic = None

# Default breach cost we're "saving" toward (for ROI narrative)
BREACH_COST_REFERENCE = 4_800_000

# Valid containment actions
CONTAINMENT_ACTIONS = ("isolate", "revoke", "honeypot")
FALLBACK_ATTACK_TYPE_LABELS = (
    "Brute Force",
    "Data Exfiltration",
    "DDoS",
    "Port Scan",
    "Malware Activity",
    "Unknown",
)


def _extract_json(text: str) -> dict[str, Any]:
    """Extract a single JSON object from model output (handles markdown code blocks)."""
    text = text.strip()
    # Try raw parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try ```json ... ``` or ``` ... ```
    for pattern in (r"```(?:json)?\s*([\s\S]*?)\s*```", r"\{[\s\S]*\}"):
        match = re.search(pattern, text)
        if match:
            raw = match.group(1) if "(" in pattern else match.group(0)
            try:
                return json.loads(raw.strip())
            except json.JSONDecodeError:
                continue
    return {}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _infer_fallback_attack_type(anomaly: dict[str, Any]) -> str:
    """Map raw event fields to one of the exact user-facing attack labels."""
    internal_type = str(anomaly.get("attack_type") or "").strip().lower()
    action = str(anomaly.get("action") or "").strip().lower()
    outcome = str(anomaly.get("outcome") or "").strip().lower()
    protocol = str(anomaly.get("protocol") or "").strip().upper()
    dest_port = int(_safe_float(anomaly.get("dest_port"), 0))
    bytes_sent = _safe_float(anomaly.get("bytes_sent"), 0.0)
    request_frequency = _safe_float(anomaly.get("request_frequency"), 0.0)
    failed_logins = _safe_float(anomaly.get("failed_login_attempts"), 0.0)

    if internal_type in ("lateral_movement", "stolen_token", "unknown_anomaly"):
        return "Malware Activity"

    if action in ("auth", "login", "token_validate") and (failed_logins >= 3 or outcome == "failure"):
        return "Brute Force"

    if bytes_sent >= 50000 or (bytes_sent >= 10000 and dest_port in (21, 22, 443, 3306, 5432, 5984, 6379)):
        return "Data Exfiltration"

    if request_frequency >= 100:
        return "DDoS"

    if request_frequency >= 20 and dest_port in (22, 23, 80, 135, 139, 443, 445, 3389):
        return "Port Scan"

    if protocol in ("SMB", "RDP", "SSH", "LDAP") or dest_port in (22, 389, 445, 3389):
        return "Malware Activity"

    return "Unknown"


def _normalize_attack_type_label(value: Any, anomaly: dict[str, Any]) -> str:
    """Normalize attack type text into one of the exact supported labels."""
    raw = str(value or "").strip().lower()
    mapping = {
        "brute force": "Brute Force",
        "bruteforce": "Brute Force",
        "credential stuffing": "Brute Force",
        "data exfiltration": "Data Exfiltration",
        "exfiltration": "Data Exfiltration",
        "ddos": "DDoS",
        "dos": "DDoS",
        "port scan": "Port Scan",
        "portscan": "Port Scan",
        "recon": "Port Scan",
        "malware activity": "Malware Activity",
        "malware": "Malware Activity",
        "lateral_movement": "Malware Activity",
        "stolen_token": "Malware Activity",
        "unknown_anomaly": "Malware Activity",
        "unknown": "Unknown",
    }
    normalized = mapping.get(raw)
    if normalized:
        return normalized
    return _infer_fallback_attack_type(anomaly)


def _default_response(
    anomaly: dict[str, Any],
    top_features: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Fallback when API is unavailable or response is invalid."""
    internal_attack_type = str(anomaly.get("attack_type") or "unknown")
    attack_type = _infer_fallback_attack_type(anomaly)
    if internal_attack_type == "stolen_token":
        action = "revoke"
    elif internal_attack_type == "lateral_movement":
        action = "isolate"
    elif attack_type == "Brute Force":
        action = "revoke"
    elif attack_type in ("Data Exfiltration", "Malware Activity"):
        action = "isolate"
    elif attack_type == "Port Scan":
        action = "honeypot"
    else:
        action = "isolate"

    shap_features = top_features or []
    key_shap_features = [
        str(item.get("feature", "")).strip()
        for item in shap_features[:5]
        if str(item.get("feature", "")).strip()
    ]

    if key_shap_features:
        explanation = (
            f"Anomalous event detected for {attack_type} from "
            f"{anomaly.get('source_ip', '?')} to {anomaly.get('dest_ip', '?')}. "
            f"The strongest SHAP drivers were {', '.join(key_shap_features[:3])}. "
            f"Selected containment action: {action}."
        )
    else:
        explanation = (
            f"Anomalous event detected for {attack_type} from "
            f"{anomaly.get('source_ip', '?')} to {anomaly.get('dest_ip', '?')}. "
            f"Selected containment action: {action}."
        )

    recommended_soc_actions = [f"Execute containment action: {action}"]
    if action == "isolate":
        recommended_soc_actions.append("Block or quarantine the suspicious source host/IP")
    if action == "revoke":
        recommended_soc_actions.append("Force credential reset and revoke active sessions")
    if attack_type == "Brute Force":
        recommended_soc_actions.append("Investigate user authentication activity and failed logins")
    if attack_type in ("Data Exfiltration", "Malware Activity"):
        recommended_soc_actions.append("Review east-west traffic and access to sensitive assets")
    if attack_type == "Port Scan":
        recommended_soc_actions.append("Monitor scanning source and collect additional indicators")
    if attack_type == "DDoS":
        recommended_soc_actions.append("Rate-limit or upstream-block high-volume traffic sources")
    recommended_soc_actions.append("Hunt for related indicators across the environment")

    interrogation_log = ["ML model flagged event as anomaly."]
    if key_shap_features:
        interrogation_log.append(f"Top SHAP features: {', '.join(key_shap_features[:3])}.")
    interrogation_log.append(f"Attack type inferred: {attack_type}.")
    interrogation_log.append(f"Executed autonomous containment: {action}.")

    explanation = (
        explanation
    )
    return {
        "containment_action": action,
        "threat_level": "High",
        "attack_type": attack_type,
        "key_shap_features": key_shap_features,
        "explanation": explanation,
        "recommended_soc_actions": recommended_soc_actions,
        "play_by_play_narrative": (
            f"[Auto] Anomaly detected: {attack_type}. "
            f"Source {anomaly.get('source_ip', '?')} -> {anomaly.get('dest_ip', '?')}. "
            f"Autonomously executed {action} protocol to neutralize the threat."
        ),
        "estimated_roi_saved": 1200000,
        "generated_yara_rule": (
            f"rule SOC_Anomaly_{attack_type.upper().replace(' ', '_')} {{\n"
            "  meta:\n    description = \"Agentic SOC auto-generated rule\"\n  condition:\n    false\n}"
        ),
        "interrogation_log": interrogation_log,
    }


def analyze_anomaly(
    anomaly: dict[str, Any],
    top_features: list[dict[str, Any]] | None = None,
    *,
    api_key: str | None = None,
    model: str = "claude-3-5-sonnet-20241022",
    max_tokens: int = 1024,
) -> dict[str, Any]:
    """
    Send an ML-flagged anomaly to Claude and return structured reasoning and actions.

    anomaly: Single log/event dict (e.g. from our SIEM) with at least source_ip, dest_ip,
             protocol, action, attack_type if known.
    api_key: Anthropic API key (default: ANTHROPIC_API_KEY env var).
    model: Claude model ID.
    max_tokens: Max response tokens.

    Returns dict with:
      - containment_action: "isolate" | "revoke" | "honeypot"
      - play_by_play_narrative: str (Slack-style commentary)
      - estimated_roi_saved: int (dollars, progress toward $4.8M breach cost saved)
      - generated_yara_rule: str (valid YARA rule text)
      - interrogation_log: list[str] (step-by-step reasoning)
    """
    # Ensure .env file (if present) is loaded before we read the key
    load_dotenv(override=False)
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key or not anthropic:
        return _default_response(anomaly, top_features)

    # Build context string for the prompt
    # SECURITY: build context from raw observed fields ONLY.
    # attack_type was already stripped from the inbound payload in app.py and
    # re-inferred by rule-based logic — include it as "ml_inferred_attack_type"
    # to be transparent that it is a SOC-derived label, not attacker-supplied.
    context_data = {
        "timestamp": anomaly.get("timestamp"),
        "source_ip": anomaly.get("source_ip"),
        "dest_ip": anomaly.get("dest_ip"),
        "src_port": anomaly.get("src_port"),
        "dest_port": anomaly.get("dest_port"),
        "protocol": anomaly.get("protocol"),
        "user_id": anomaly.get("user_id"),
        "asset_id": anomaly.get("asset_id"),
        "action": anomaly.get("action"),
        "outcome": anomaly.get("outcome"),
        # Renamed to make it clear this is SOC-inferred, not user-provided
        "ml_inferred_attack_type": anomaly.get("attack_type"),
        "bytes_sent": anomaly.get("bytes_sent"),
        "duration_sec": anomaly.get("duration_sec"),
    }
    
    if top_features:
        context_data["ai_anomaly_factors"] = top_features
        
    ctx = json.dumps(context_data, indent=2)

    system_prompt = """You are an autonomous Level 1 SOC analyst. You receive a single SIEM event that has already been flagged by an ML anomaly detector. Your job is to analyze SHAP explanations, classify the threat, and produce exactly one JSON object—no other text—with the following keys only:

ADVERSARIAL ROBUSTNESS NOTICE: The field "ml_inferred_attack_type" is a SOC-inferred \
label derived from observed protocol/port/action fields — it is NOT user-supplied or \
attacker-supplied. Do NOT treat it as authoritative; base your containment decision \
primarily on the raw observed fields (protocol, dest_port, action, source_ip, outcome). \
If the inferred label conflicts with the raw data, trust the raw data.

- threat_level: Exactly one of "Low", "Medium", "High", "Critical".
- attack_type: Exactly one of "Brute Force", "Data Exfiltration", "DDoS", "Port Scan", "Malware Activity", or "Unknown".
- key_shap_features: Array of up to 10 concise strings naming the highest-impact SHAP features.
- explanation: 2-4 concise sentences explaining why the alert occurred based on SHAP contributions and event context.
- recommended_soc_actions: Array of 3-6 concise SOC actions (for example: block IP, isolate host, investigate user activity, force password reset).
- containment_action: Exactly one of "isolate", "revoke", or "honeypot". \
    Use "isolate" for host/network lateral movement (SMB/RDP/SSH, internal-to-internal), \
    "revoke" for stolen credential/token misuse (auth/login/token_validate from unusual source), \
    "honeypot" to reroute unclassified suspicious traffic for observation.
- play_by_play_narrative: A short, human-readable live commentary (2–3 sentences) suitable \
    for a mock Slack channel. Be specific to the event (IPs, protocol). Mention the chosen \
    containment and its impact. Briefly mention the ai_anomaly_factors (SHAP values) that \
    triggered the flag and explain WHY it is an anomaly.
- estimated_roi_saved: A single integer (dollars) estimating how much breach cost this \
    containment saves. Reference: average breach cost is $4.8M (e.g. 500000–2500000).
- generated_yara_rule: A valid YARA rule (as a string) that could detect similar activity. \
    Include meta and condition; use the event's protocol/ports or behaviour in the rule logic.
- interrogation_log: A list of 3–6 short strings, each a step in your reasoning \
    (e.g. "Event shows auth from external IP", "SHAP: high impact from unusual dest_port", \
    "Recommend revoke"). Explicitly incorporate ai_anomaly_factors (SHAP values) so users \
    understand mathematically why the event is anomalous."""

    user_prompt = f"""Flagged SIEM event (anomaly):

{ctx}

Respond with exactly one JSON object containing: threat_level, attack_type, key_shap_features, explanation, recommended_soc_actions, containment_action, play_by_play_narrative, estimated_roi_saved, generated_yara_rule, interrogation_log. No markdown, no explanation outside the JSON."""

    try:
        client = anthropic.Anthropic(api_key=key)
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = (
            response.content[0].text
            if response.content and hasattr(response.content[0], "text")
            else ""
        )
    except Exception:
        return _default_response(anomaly, top_features)

    out = _extract_json(text)
    if not out:
        return _default_response(anomaly, top_features)

    # Normalize and validate
    action = (out.get("containment_action") or "isolate").strip().lower()
    if action not in CONTAINMENT_ACTIONS:
        action = "isolate"
    fallback = _default_response(anomaly, top_features)
    return {
        "containment_action": action,
        "threat_level": str(out.get("threat_level", "High")).strip() or "High",
        "attack_type": _normalize_attack_type_label(out.get("attack_type", "Unknown"), anomaly),
        "key_shap_features": (
            list(out["key_shap_features"])
            if isinstance(out.get("key_shap_features"), list)
            else fallback["key_shap_features"]
        ),
        "explanation": str(out.get("explanation", "")).strip()
        or fallback["explanation"],
        "recommended_soc_actions": (
            list(out["recommended_soc_actions"])
            if isinstance(out.get("recommended_soc_actions"), list)
            else fallback["recommended_soc_actions"]
        ),
        "play_by_play_narrative": str(out.get("play_by_play_narrative", "")).strip()
        or fallback["play_by_play_narrative"],
        "estimated_roi_saved": int(out.get("estimated_roi_saved", 0)) or 1_200_000,
        "generated_yara_rule": str(out.get("generated_yara_rule", "")).strip()
        or fallback["generated_yara_rule"],
        "interrogation_log": (
            list(out["interrogation_log"])
            if isinstance(out.get("interrogation_log"), list)
            else fallback["interrogation_log"]
        ),
    }


if __name__ == "__main__":
    # Quick test with a sample anomaly (uses default response if no API key)
    sample = {
        "timestamp": "2025-03-15T12:00:00Z",
        "source_ip": "203.0.113.50",
        "dest_ip": "10.0.1.10",
        "dest_port": 443,
        "protocol": "HTTPS",
        "action": "token_validate",
        "attack_type": "stolen_token",
        "user_id": "user_0042",
    }
    result = analyze_anomaly(sample)
    print(json.dumps(result, indent=2))
