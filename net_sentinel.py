import sys
import numpy as np
from sklearn.ensemble import IsolationForest

def analyze_network_logs(log_file_path):
    print(f"[*] Analyzing network logs: {log_file_path}")
    try:
        with open(log_file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: Log file {log_file_path} not found.")
        sys.exit(1)

    if not lines:
        print("[!] The log file is empty.")
        return

    features = []
    for line in lines:
        length = len(line)
        spaces = line.count(' ')
        digits = sum(c.isdigit() for c in line)
        features.append([length, spaces, digits])

    X = np.array(features)
    model = IsolationForest(contamination=0.1, random_state=42)
    predictions = model.fit_predict(X)

    print("\n[+] Analysis Complete. Flagged Network Anomalies:")
    print("-" * 60)
    
    anomalies_found = False
    for line, pred in zip(lines, predictions):
        if pred == -1:
            anomalies_found = True
            print(f" [!] ANOMALOUS PACKET/EVENT: {line}")

    if not anomalies_found:
        print(" [✓] No network anomalies detected in the sample.")
    print("-" * 60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 net_sentinel.py <path_to_network_log>")
        sys.exit(1)
    analyze_network_logs(sys.argv[1])
