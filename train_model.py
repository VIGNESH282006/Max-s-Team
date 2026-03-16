"""
The Agentic SOC - Phase 1: ML Anomaly Detection
Trains a RandomForestClassifier on synthetic SIEM logs to flag anomalies in real-time.
Saves the trained model and a minimal feature pipeline for use by the Flask API.
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_PATH = Path("data/synthetic_logs.jsonl")
MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "anomaly_rf_model.joblib"
ENCODERS_PATH = MODEL_DIR / "encoders.joblib"
RANDOM_STATE = 42

# Protocol/action sets for consistent encoding at inference
PROTOCOLS_ORDER = ["TCP", "UDP", "HTTP", "HTTPS", "SMB", "RDP", "SSH", "LDAP"]
ACTIONS_ORDER = ["auth", "connection", "file_access", "dns_query", "api_call", "login", "token_validate"]
OUTCOMES_ORDER = ["success", "failure", "timeout"]


def _is_internal(ip: str) -> int:
    if not ip or not isinstance(ip, str):
        return 0
    return 1 if any(ip.startswith(p) for p in ("10.0.", "192.168.", "172.16.")) else 0


def load_logs(path: Path) -> pd.DataFrame:
    """Load JSONL logs into a DataFrame."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pd.DataFrame(rows)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build numeric/categorical features for ML from raw log fields."""
    # Binary: internal vs external
    df = df.copy()
    df["source_internal"] = df["source_ip"].map(_is_internal)
    df["dest_internal"] = df["dest_ip"].map(_is_internal)

    # Numeric
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0)
    df["duration_sec"] = pd.to_numeric(df["duration_sec"], errors="coerce").fillna(0)
    df["dest_port"] = pd.to_numeric(df["dest_port"], errors="coerce").fillna(0)
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)

    # Port bins (high-risk ports often used in attacks)
    df["dest_port_high_risk"] = df["dest_port"].isin([22, 445, 3389, 5985, 389]).astype(int)

    # Categorical -> numeric via mapping (consistent at train and inference)
    df["protocol_ord"] = df["protocol"].astype(str).map(
        lambda x: PROTOCOLS_ORDER.index(x) if x in PROTOCOLS_ORDER else -1
    )
    df["action_ord"] = df["action"].astype(str).map(
        lambda x: ACTIONS_ORDER.index(x) if x in ACTIONS_ORDER else -1
    )
    df["outcome_ord"] = df["outcome"].astype(str).map(
        lambda x: OUTCOMES_ORDER.index(x) if x in OUTCOMES_ORDER else -1
    )

    feature_cols = [
        "source_internal",
        "dest_internal",
        "bytes_sent",
        "duration_sec",
        "dest_port",
        "src_port",
        "dest_port_high_risk",
        "protocol_ord",
        "action_ord",
        "outcome_ord",
    ]
    return df[feature_cols]


def train(data_path: Path | None = None, model_dir: Path | None = None) -> dict:
    """
    Load data, build features, train RandomForest, save model and encoders.
    Returns metrics dict (accuracy, report, etc.).
    """
    data_path = data_path or DATA_PATH
    model_dir = model_dir or MODEL_DIR
    model_dir.mkdir(parents=True, exist_ok=True)

    if not data_path.exists():
        raise FileNotFoundError(
            f"Data not found: {data_path}. Run: python log_generator.py"
        )

    print("Loading logs...")
    df = load_logs(data_path)
    y = np.array(df["is_anomaly"], dtype=int)
    X = build_features(df)

    # Handle any remaining NaN
    X = X.fillna(0)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(
        y_test, y_pred, target_names=["normal", "anomaly"], output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["normal", "anomaly"]))
    print("Confusion Matrix:")
    print(cm)

    # Save model and feature metadata for inference
    joblib.dump(clf, model_dir / "anomaly_rf_model.joblib")
    encoders_meta = {
        "feature_columns": list(X.columns),
        "protocols_order": PROTOCOLS_ORDER,
        "actions_order": ACTIONS_ORDER,
        "outcomes_order": OUTCOMES_ORDER,
    }
    joblib.dump(encoders_meta, model_dir / "encoders.joblib")

    print(f"\nModel saved to {model_dir / 'anomaly_rf_model.joblib'}")
    print(f"Encoders/metadata saved to {model_dir / 'encoders.joblib'}")

    return {
        "accuracy": float(report["accuracy"]),
        "precision_anomaly": float(report["anomaly"]["precision"]),
        "recall_anomaly": float(report["anomaly"]["recall"]),
        "f1_anomaly": float(report["anomaly"]["f1-score"]),
        "confusion_matrix": cm.tolist(),
    }


if __name__ == "__main__":
    train()
