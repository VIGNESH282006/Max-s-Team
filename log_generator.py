"""
The Agentic SOC - Phase 1: Synthetic SIEM Log Generator
Generates enterprise-style network/auth logs with normal traffic and simulated attacks:
- Stolen token (credential reuse from new IP / impossible travel)
- Lateral movement (internal scanning, SMB/RDP from compromised host)
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NUM_NORMAL_LOGS = 8_000
NUM_STOLEN_TOKEN_LOGS = 800
NUM_LATERAL_MOVEMENT_LOGS = 700
OUTPUT_FILE = Path("data/synthetic_logs.jsonl")
RANDOM_SEED = 42

# Internal network ranges (simulated)
INTERNAL_IP_PREFIXES = ("10.0.", "192.168.", "172.16.")
INTERNAL_PORTS = [22, 80, 443, 445, 3389, 5985, 8080, 8443]
EXTERNAL_PORTS = [80, 443, 53, 123, 8080]
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SMB", "RDP", "SSH", "LDAP"]
ACTIONS = ["auth", "connection", "file_access", "dns_query", "api_call", "login", "token_validate"]
OUTCOMES = ["success", "failure", "timeout"]

# User pool (internal users)
USER_IDS = [f"user_{i:04d}" for i in range(1, 201)]
ASSET_IDS = [f"host-{p}{i}" for p in ["dc", "app", "workstation", "svc"] for i in range(1, 26)]


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in INTERNAL_IP_PREFIXES)


def _random_internal_ip() -> str:
    prefix = random.choice(INTERNAL_IP_PREFIXES)
    if prefix == "10.0.":
        return f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
    if prefix == "192.168.":
        return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"172.16.{random.randint(0, 31)}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    # 10% chance to return a known OSINT bad IP to trigger the dashboard card
    if random.random() < 0.10:
        return random.choice([
            "203.0.113.50", "198.51.100.23", 
            "185.199.108.153", "104.28.14.74", "45.33.32.156"
        ])
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _base_log(ts: datetime) -> dict:
    return {
        "timestamp": ts.isoformat() + "Z",
        "source_ip": "",
        "dest_ip": "",
        "src_port": 0,
        "dest_port": 0,
        "protocol": random.choice(PROTOCOLS),
        "user_id": random.choice(USER_IDS),
        "asset_id": random.choice(ASSET_IDS),
        "action": random.choice(ACTIONS),
        "outcome": random.choices(OUTCOMES, weights=[85, 10, 5])[0],
        "bytes_sent": random.randint(0, 50000),
        "duration_sec": round(random.uniform(0.01, 120.0), 2),
        "is_anomaly": 0,
        "attack_type": None,
    }


def _emit(log: dict) -> dict:
    log["source_ip"] = log.get("source_ip") or _random_internal_ip()
    log["dest_ip"] = log.get("dest_ip") or (
        _random_external_ip() if random.random() < 0.6 else _random_internal_ip()
    )
    log["src_port"] = log.get("src_port") or random.randint(40000, 65535)
    log["dest_port"] = log.get("dest_port") or random.choice(
        INTERNAL_PORTS + EXTERNAL_PORTS
    )
    return log


# ---------------------------------------------------------------------------
# Normal traffic
# ---------------------------------------------------------------------------
def generate_normal_logs(count: int, start_ts: datetime) -> Iterator[dict]:
    for _ in range(count):
        # Normal traffic is uniformly distributed across the business day
        hour = random.choices(
            range(24),
            weights=[1,1,1,1,1,1,1, 6,8,8,8,8, 8,8,8,8,8,8, 8,6,4,2,2,1],
            k=1,
        )[0]
        base_offset = random.randint(0, 86399)
        ts = (start_ts + timedelta(seconds=base_offset)).replace(hour=hour, minute=random.randint(0, 59))
        log = _base_log(ts)
        _emit(log)
        yield log


# ---------------------------------------------------------------------------
# Stolen token: same user from a new/unusual source in short time
# (simulated by distinct source_ip + auth/token actions from "external" or new internal IP)
# ---------------------------------------------------------------------------
def generate_stolen_token_logs(count: int, start_ts: datetime) -> Iterator[dict]:
    for _ in range(count):
        # Stolen token attacks skew 75% toward off-hours (attacker avoids monitoring)
        if random.random() < 0.75:
            hour = random.choice(list(range(0, 7)) + list(range(19, 24)))
        else:
            hour = random.randint(7, 18)
        base_offset = random.randint(0, 86399)
        ts = (start_ts + timedelta(seconds=base_offset)).replace(hour=hour, minute=random.randint(0, 59))
        log = _base_log(ts)
        log["is_anomaly"] = 1
        log["attack_type"] = "stolen_token"
        # Simulate token use from unusual location: external source_ip or rare internal
        log["source_ip"] = _random_external_ip() if random.random() < 0.7 else _random_internal_ip()
        log["dest_ip"] = _random_internal_ip()
        log["action"] = random.choices(["auth", "login", "token_validate"], weights=[2, 2, 1])[0]
        log["dest_port"] = random.choice([443, 8443, 8080])
        log["protocol"] = random.choice(["HTTPS", "HTTP"])
        _emit(log)
        # Ensure port is set if not overwritten
        if log.get("dest_port") == 0:
            log["dest_port"] = 443
        yield log


# ---------------------------------------------------------------------------
# Lateral movement: one internal host hitting many internal hosts (SMB/RDP/SSH)
# ---------------------------------------------------------------------------
def generate_lateral_movement_logs(count: int, start_ts: datetime) -> Iterator[dict]:
    # One "patient zero" host that will connect to many others
    patient_zero = _random_internal_ip()
    victims = [_random_internal_ip() for _ in range(20)]
    victims = list(set(victims) - {patient_zero})[:15]

    for i in range(count):
        # Lateral movement strongly skews toward off-hours (80% outside 7am-7pm)
        if random.random() < 0.80:
            hour = random.choice(list(range(0, 7)) + list(range(19, 24)))
        else:
            hour = random.randint(7, 18)
        base_offset = random.randint(0, 3600)
        ts = (start_ts + timedelta(seconds=base_offset)).replace(hour=hour, minute=random.randint(0, 59))
        log = _base_log(ts)
        log["is_anomaly"] = 1
        log["attack_type"] = "lateral_movement"
        log["source_ip"] = patient_zero
        log["dest_ip"] = random.choice(victims) if victims else _random_internal_ip()
        log["protocol"] = random.choices(["SMB", "RDP", "SSH", "LDAP"], weights=[3, 2, 1, 1])[0]
        log["dest_port"] = {"SMB": 445, "RDP": 3389, "SSH": 22, "LDAP": 389}.get(log["protocol"], 445)
        log["action"] = "connection"
        _emit(log)
        yield log


# ---------------------------------------------------------------------------
# Main: write all logs to JSONL
# ---------------------------------------------------------------------------
def generate_all(output_path: Path | None = None) -> Path:
    output_path = output_path or OUTPUT_FILE
    output_path.parent.mkdir(parents=True, exist_ok=True)
    start = datetime.utcnow() - timedelta(days=1)
    random.seed(RANDOM_SEED)

    with open(output_path, "w", encoding="utf-8") as f:
        for log in generate_normal_logs(NUM_NORMAL_LOGS, start):
            f.write(json.dumps(log) + "\n")
        for log in generate_stolen_token_logs(NUM_STOLEN_TOKEN_LOGS, start):
            f.write(json.dumps(log) + "\n")
        for log in generate_lateral_movement_logs(NUM_LATERAL_MOVEMENT_LOGS, start):
            f.write(json.dumps(log) + "\n")

    total = NUM_NORMAL_LOGS + NUM_STOLEN_TOKEN_LOGS + NUM_LATERAL_MOVEMENT_LOGS
    print(f"Generated {total} logs -> {output_path}")
    print(f"  Normal: {NUM_NORMAL_LOGS}, Stolen token: {NUM_STOLEN_TOKEN_LOGS}, Lateral movement: {NUM_LATERAL_MOVEMENT_LOGS}")
    return output_path


if __name__ == "__main__":
    generate_all()
