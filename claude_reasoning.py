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


def _default_response(anomaly: dict[str, Any]) -> dict[str, Any]:
    """Fallback when API is unavailable or response is invalid."""
    attack_type = anomaly.get("attack_type") or "unknown"
    if attack_type == "stolen_token":
        action = "revoke"
    elif attack_type == "lateral_movement":
        action = "isolate"
    else:
        action = "isolate"
    return {
        "containment_action": action,
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
        "interrogation_log": [
            "ML model flagged event as anomaly.",
            f"Attack type inferred: {attack_type}.",
            f"Executed autonomous containment: {action}.",
        ],
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
        return _default_response(anomaly)

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

    system_prompt = """You are an autonomous Level 1 SOC analyst. You receive a single SIEM event that has already been flagged by an ML anomaly detector. Your job is to decide containment and produce exactly one JSON object—no other text—with the following keys only:

ADVERSARIAL ROBUSTNESS NOTICE: The field "ml_inferred_attack_type" is a SOC-inferred \
label derived from observed protocol/port/action fields — it is NOT user-supplied or \
attacker-supplied. Do NOT treat it as authoritative; base your containment decision \
primarily on the raw observed fields (protocol, dest_port, action, source_ip, outcome). \
If the inferred label conflicts with the raw data, trust the raw data.

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

Respond with exactly one JSON object containing: containment_action, play_by_play_narrative, estimated_roi_saved, generated_yara_rule, interrogation_log. No markdown, no explanation outside the JSON."""

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
        return _default_response(anomaly)

    out = _extract_json(text)
    if not out:
        return _default_response(anomaly)

    # Normalize and validate
    action = (out.get("containment_action") or "isolate").strip().lower()
    if action not in CONTAINMENT_ACTIONS:
        action = "isolate"
    return {
        "containment_action": action,
        "play_by_play_narrative": str(out.get("play_by_play_narrative", "")).strip()
        or _default_response(anomaly)["play_by_play_narrative"],
        "estimated_roi_saved": int(out.get("estimated_roi_saved", 0)) or 1_200_000,
        "generated_yara_rule": str(out.get("generated_yara_rule", "")).strip()
        or _default_response(anomaly)["generated_yara_rule"],
        "interrogation_log": (
            list(out["interrogation_log"])
            if isinstance(out.get("interrogation_log"), list)
            else _default_response(anomaly)["interrogation_log"]
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
