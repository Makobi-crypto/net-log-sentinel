#!/usr/bin/env python3
"""
net_sentinel.py - Real-Time AI Network Log Anomaly Detector using Isolation Forest.
Supports static file scanning, real-time live tailing (--follow), and JSON exports.
"""

import argparse
import datetime
import json
import math
import os
import re
import sys
import time
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+\S+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)

def parse_log_time(time_str: str) -> datetime.datetime:
    try:
        clean_time = time_str.split()[0]
        return datetime.datetime.strptime(clean_time, "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return datetime.datetime.now()

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob if p > 0])

def parse_single_line(line: str, line_num: int = 0):
    line = line.strip()
    if not line:
        return None
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    data = match.groupdict()
    bytes_sent = int(data["bytes"]) if data["bytes"].isdigit() else 0
    status_code = int(data["status"])
    return {
        "line_num": line_num,
        "ip": data["ip"],
        "timestamp": parse_log_time(data["time"]),
        "method": data["method"].upper(),
        "path": data["path"],
        "status": status_code,
        "bytes": bytes_sent,
        "raw": line
    }

def parse_log_file(file_path: str):
    records = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            parsed = parse_single_line(line, idx)
            if parsed:
                records.append(parsed)
    return records

def extract_single_feature(record, recent_ip_timestamps):
    log_bytes = math.log1p(record["bytes"])
    ts = record["timestamp"]
    window_start = ts - datetime.timedelta(seconds=30)
    window_end = ts + datetime.timedelta(seconds=30)
    
    # Count requests from this IP in the 30-sec window
    req_count = sum(1 for t in recent_ip_timestamps[record["ip"]] if window_start <= t <= window_end)

    status = record["status"]
    if 200 <= status < 300:
        status_risk = 0.0
    elif 300 <= status < 400:
        status_risk = 0.5
    elif 400 <= status < 500:
        status_risk = 2.0
    else:
        status_risk = 3.0

    method = record["method"]
    if method == "GET":
        method_score = 1.0
    elif method in ("POST", "PUT"):
        method_score = 2.0
    else:
        method_score = 3.0

    path_ent = calculate_entropy(record["path"])
    path_len = len(record["path"])

    return [log_bytes, float(req_count), status_risk, method_score, path_ent, float(path_len)]

def extract_features_batch(records):
    if not records:
        return np.empty((0, 6)), []

    records.sort(key=lambda x: x["timestamp"])
    ip_timestamps = defaultdict(list)
    for r in records:
        ip_timestamps[r["ip"]].append(r["timestamp"])

    features = [extract_single_feature(r, ip_timestamps) for r in records]
    return np.array(features), records

def generate_sample_log(output_path: str = "sample_traffic.log", total_lines: int = 400):
    import random
    normal_ips = [f"192.168.1.{i}" for i in range(10, 25)]
    normal_paths = ["/", "/index.html", "/about", "/api/v1/status", "/products", "/cart", "/login", "/dashboard"]
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
    entries = []

    for i in range(total_lines):
        t = base_time + datetime.timedelta(seconds=i * 12 + random.randint(1, 5))
        ip = random.choice(normal_ips)
        path = random.choice(normal_paths)
        method = "POST" if path in ("/login", "/cart") else "GET"
        status = 200 if random.random() > 0.05 else 404
        bytes_sent = random.randint(300, 4500)
        time_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        entries.append(f'{ip} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {bytes_sent}')

    # Injected Exfiltration Anomaly
    exfil_time = (base_time + datetime.timedelta(minutes=40)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    entries.append(f'10.0.0.99 - - [{exfil_time}] "POST /internal/db_dump.sql HTTP/1.1" 200 68291040')

    # Injected Directory Fuzzing Spike
    spike_base = base_time + datetime.timedelta(minutes=70)
    for s in range(15):
        s_time = (spike_base + datetime.timedelta(milliseconds=s * 150)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        entries.append(f'203.0.113.42 - - [{s_time}] "GET /etc/shadow?fuzz={s} HTTP/1.1" 404 182')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(entries) + "\n")
    print(f"[*] Synthetic log generated: {output_path}")

def live_tail(log_path: str, model, ip_history):
    """Watches log file in real time (tail -f style) and flags incoming anomalies."""
    print(f"[*] Live Sentinel active. Monitoring {log_path} for real-time anomalies... (Ctrl+C to stop)")
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            record = parse_single_line(line)
            if not record:
                continue

            ip_history[record["ip"]].append(record["timestamp"])
            feat = extract_single_feature(record, ip_history)
            feat_arr = np.array([feat])

            pred = model.predict(feat_arr)[0]
            score = round(float(model.decision_function(feat_arr)[0]), 4)

            if pred == -1:
                print(f"\n[LIVE ALERT] Anomaly Detected! (Score: {score})")
                print(f"  Source IP : {record['ip']}")
                print(f"  Request   : {record['method']} {record['path']}")
                print(f"  Status    : {record['status']} | Payload: {record['bytes']} bytes")
                print(f"  Time      : {record['timestamp'].strftime('%H:%M:%S')}")
                print("-" * 65)

def run_sentinel(log_path: str, contamination: float = 0.03, n_estimators: int = 150, 
                 export_json: str = None, follow: bool = False):
    if not os.path.exists(log_path):
        print(f"[!] Error: File '{log_path}' not found.")
        sys.exit(1)

    print(f"[*] Reading {log_path} for baseline training...")
    records = parse_log_file(log_path)
    if not records:
        print("[!] No valid records found.")
        sys.exit(1)

    X, parsed_records = extract_features_batch(records)
    print(f"[*] Training Isolation Forest on {len(records)} events...")
    model = IsolationForest(contamination=contamination, n_estimators=n_estimators, random_state=42)
    predictions = model.fit_predict(X)
    scores = model.decision_function(X)

    anomalies = []
    ip_history = defaultdict(lambda: deque(maxlen=200))
    for r in records:
        ip_history[r["ip"]].append(r["timestamp"])

    for idx, (pred, score) in enumerate(zip(predictions, scores)):
        if pred == -1:
            rec = parsed_records[idx]
            anomalies.append({
                "line": rec["line_num"],
                "ip": rec["ip"],
                "timestamp": rec["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "method": rec["method"],
                "path": rec["path"],
                "status": rec["status"],
                "bytes": rec["bytes"],
                "anomaly_score": round(float(score), 4),
                "raw": rec["raw"]
            })

    print(f"\n{'='*75}\n BATCH ANOMALY REPORT (Analyzed: {len(records)} | Flagged: {len(anomalies)})\n{'='*75}\n")
    anomalies.sort(key=lambda x: x["anomaly_score"])
    for a in anomalies:
        print(f"[ALERT] Line {a['line']} | IP: {a['ip']} | Score: {a['anomaly_score']}")
        print(f"        {a['method']} {a['path']} | Status: {a['status']} | Size: {a['bytes']}B")
        print("-" * 75)

    if export_json:
        with open(export_json, "w", encoding="utf-8") as jf:
            json.dump(anomalies, jf, indent=2)
        print(f"[+] Saved {len(anomalies)} anomaly reports to: {export_json}")

    if follow:
        try:
            live_tail(log_path, model, ip_history)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")

def main():
    parser = argparse.ArgumentParser(description="net-log-sentinel: AI Log Anomaly Detector")
    parser.add_argument("logfile", nargs="?", help="Path to access/network log")
    parser.add_argument("--generate-sample", action="store_true", help="Generate sample traffic log")
    parser.add_argument("--contamination", type=float, default=0.03, help="Contamination rate (default: 0.03)")
    parser.add_argument("--estimators", type=int, default=150, help="Number of trees (default: 150)")
    parser.add_argument("--export-json", type=str, default=None, help="Save anomalies to a JSON file")
    parser.add_argument("-f", "--follow", action="store_true", help="Real-time live tailing mode")

    args = parser.parse_args()

    if args.generate_sample:
        target = args.logfile if args.logfile else "sample_traffic.log"
        generate_sample_log(target)
        if not args.logfile:
            return

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    run_sentinel(
        args.logfile,
        contamination=args.contamination,
        n_estimators=args.estimators,
        export_json=args.export_json,
        follow=args.follow
    )

if __name__ == "__main__":
    main()
