"""
The Agentic SOC - Phase 4: Adaptability & Retraining Pipeline

Loads original synthetic logs + analyst feedback,
retrains the ML and IF models, and hot-swaps them.
"""

from pathlib import Path
import json

from train_model import load_logs, train, DATA_PATH, MODEL_DIR

FEEDBACK_PATH = Path("data/feedback.jsonl")
COMBINED_PATH = Path("data/combined_logs_for_retraining.jsonl")

def execute_retraining():
    print("=== Agentic SOC Retraining Pipeline ===")
    
    # 1. Gather all logs
    all_logs = []
    
    if DATA_PATH.exists():
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    all_logs.append(line.strip())
                    
    feedback_count = 0
    if FEEDBACK_PATH.exists():
        with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    all_logs.append(line.strip())
                    feedback_count += 1
                    
    print(f"Loaded {len(all_logs) - feedback_count} original logs.")
    print(f"Loaded {feedback_count} feedback logs from analysts.")
    
    # 2. Write combined to disk for train_model.py to consume
    with open(COMBINED_PATH, "w", encoding="utf-8") as f:
        for log_str in all_logs:
            f.write(log_str + "\n")
            
    print("Triggering model training on augmented dataset...")
    metrics = train(data_path=COMBINED_PATH, model_dir=MODEL_DIR)
    
    print("\n[SUCCESS] Models retrained and hot-swapped for Flask API.")
    print(f"New RF Accuracy: {metrics['accuracy']:.4f}")

if __name__ == "__main__":
    execute_retraining()
