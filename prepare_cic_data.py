import pandas as pd
import json
import random
from pathlib import Path
import os
from datetime import datetime

# Paths
CIC_DIR = Path("cic dataset")
OUT_FILE = Path("data/synthetic_logs.jsonl")

# We need to map CIC data to our required schema.
# The schema expected by train_model.py and app.py:
# timestamp, source_ip, dest_ip, src_port, dest_port, protocol,
# user_id, asset_id, action, outcome, bytes_sent, duration_sec,
# failed_login_attempts, user_privilege, request_frequency, attack_type, is_anomaly

def convert_cic_to_synthetic(max_samples_per_file=20000):
    all_logs = []
    
    csv_files = list(CIC_DIR.glob("*.csv"))
    if not csv_files:
        print("No CSV files found in 'cic dataset' folder.")
        return
        
    for file_path in csv_files:
        print(f"Processing {file_path.name}...")
        try:
            # Read a sample of rows to avoid MemoryError
            df = pd.read_csv(file_path).sample(frac=1, random_state=42)
            
            # Clean column names
            df.columns = df.columns.str.strip()
            
            # Select relevant rows, balance benign vs anomaly if possible
            anomalies = df[df['Label'] != 'BENIGN']
            benign = df[df['Label'] == 'BENIGN']
            
            # Sample to keep it balanced and manageable
            sample_size = min(len(anomalies), max_samples_per_file // 2) if len(anomalies) > 0 else 0
            
            if sample_size > 0:
                sampled_anomalies = anomalies.sample(n=sample_size, random_state=42)
                sampled_benign = benign.sample(n=sample_size, random_state=42)
                sampled_df = pd.concat([sampled_anomalies, sampled_benign])
            else:
                sampled_size = min(len(benign), max_samples_per_file)
                sampled_df = benign.sample(n=sampled_size, random_state=42)
                
            for _, row in sampled_df.iterrows():
                label = row['Label']
                is_anomaly = 1 if label != 'BENIGN' else 0
                
                # Synthetic Mappings
                # IPs: BENIGN -> internal source; ANOMALY -> external source (usually)
                source_ip = "10.0.5.5" if not is_anomaly else "203.0.113.100"
                dest_ip = "10.0.0.10"
                
                dest_port = int(row.get('Destination Port', random.randint(1024, 65535)))
                
                # Duration in seconds (CIC duration is in microseconds)
                duration_micro = row.get('Flow Duration', 0)
                duration_sec = float(duration_micro) / 1_000_000.0
                
                # Bytes sent
                fwd_bytes = row.get('Total Length of Fwd Packets', 0)
                bwd_bytes = row.get('Total Length of Bwd Packets', 0)
                bytes_sent = int(fwd_bytes) + int(bwd_bytes)
                
                # Others
                protocol = "TCP"  # Defaulting, as some CIC datasets lack Protocol
                action = "connection"
                outcome = "success"
                
                # If it's a known attack port or label, modify action/outcome
                if 'Web' in str(label):
                    action = "api_call"
                elif 'Brute' in str(label) or dest_port in [22, 3389]:
                    action = "login"
                    outcome = "failure" if is_anomaly else "success"
                
                attack_type = str(label) if is_anomaly else None
                
                log_idx = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "src_port": random.randint(10000, 60000),
                    "dest_port": dest_port,
                    "protocol": protocol,
                    "user_id": "system",
                    "asset_id": "server-01",
                    "action": action,
                    "outcome": outcome,
                    "bytes_sent": bytes_sent,
                    "duration_sec": duration_sec,
                    "failed_login_attempts": 5 if (action == 'login' and is_anomaly) else 0,
                    "user_privilege": "guest" if is_anomaly else "user",
                    "request_frequency": 1 if not is_anomaly else random.randint(5, 50),
                    "attack_type": attack_type,
                    "is_anomaly": is_anomaly
                }
                all_logs.append(log_idx)
                
        except Exception as e:
            print(f"Error reading {file_path.name}: {e}")
            
    # Write to jsonl
    print(f"Writing {len(all_logs)} mapped logs to {OUT_FILE}")
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, 'w') as f:
        for log in all_logs:
            f.write(json.dumps(log) + "\n")
            
    print("Done. Ready to train model.")

if __name__ == "__main__":
    convert_cic_to_synthetic()
