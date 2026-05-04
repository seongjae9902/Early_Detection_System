from collections import deque
import subprocess
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

FEATURES = ["packet_count", "total_bytes", "avg_bytes", "iat_mean"]

def compute_features(buffer):
    if not buffer:
        return None
    
    times = [x[0] for x in buffer]
    sizes = [x[1] for x in buffer]

    packet_count = len(sizes)
    total_bytes = sum(sizes)
    avg_bytes = total_bytes / packet_count if packet_count > 0 else 0

    if len(times) > 1:
        iats = np.diff(times)
        iat_mean = float(np.mean(iats))
    else:
        iat_mean = 0.0
    
    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_bytes": avg_bytes,
        "iat_mean": iat_mean
    }

def classify_score(score, base_threshold, ext_threshold):
    if score > ext_threshold:
        return "ATTACK"
    elif score > base_threshold:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

def monitor(interface, model, base_threshold, ext_threshold, window_size=5, step_size=1):
    recent_scores = deque(maxlen=30)
    risk_window = deque(maxlen=10)

    history = []
    step_count = 0
    
    buffer = deque()
    last_eval = time.time()

    cmd = [
        "sudo",
        "tshark",
        "-i", interface,
        "-l",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len"
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    print("==== Real-Time Monitoring Started ====")
    print(f"Interface   : {interface}")
    print(f"Window Size : {window_size} sec")
    print(f"Step Size   : {step_size} sec")
    print("-" * 50)

    try:
        while True:
            line = process.stdout.readline().strip()
            #print("RAW:", repr(line))

            if line:
                parts = line.split("\t")
                if len(parts) == 2:
                    try:
                        pkt_time = float(parts[0])
                        pkt_size = int(parts[1])
                        buffer.append((pkt_time, pkt_size))
                    except ValueError:
                        pass
            
            #print("Buffer Size:", len(buffer))
            current_time = time.time()

            # Recent 5 seconds
            while buffer and buffer[0][0] < current_time - window_size:
                buffer.popleft()

            #print("NOW:", current_time)
            #if buffer:
            #    print("OLDEST", buffer[0][0], "NEWEST", buffer[-1][0])
            # Evaluate every 1 second
            if current_time - last_eval >= step_size:
                feat = compute_features(buffer)

                if feat is not None:
                    X = pd.DataFrame([feat])[FEATURES]
                    score = -model.decision_function(X)[0]

                    if score > ext_threshold:
                        risk_window.append(1)
                    else:
                        risk_window.append(0)
                    
                    high_risk = sum(risk_window) >= 3

                    if not high_risk and score < ext_threshold:
                        recent_scores.append(score)
                    
                    if not high_risk and len(recent_scores) >= 30:
                        recent_p95 = np.percentile(list(recent_scores), 95)
                        base_threshold =0.8 * base_threshold + 0.2 * recent_p95
                    
                    level = classify_score(score, base_threshold, ext_threshold)

                    history.append({
                        "step": step_count,
                        "anomaly_score": score,
                        "base_threshold": base_threshold,
                        "ext_threshold": ext_threshold,
                        "level": level,
                        "high_risk": high_risk
                    })

                    step_count += 1

                    print(f"Level          : {level}")
                    print(f"Packet Count   : {feat['packet_count']}")
                    print(f"Total Bytes    : {feat['total_bytes']} bytes")
                    print(f"Avg Packet     : {feat['avg_bytes']:.2f} bytes")
                    print(f"IAT Mean       : {feat['iat_mean']:.4f} sec")
                    print(f"Anomaly Score  : {score:.6f}")
                    print(f"Base Threshold : {base_threshold:.6f}")
                    print(f"Extreme Thresh : {ext_threshold:.6f}")
                    print(f"High Risk      : {high_risk}")
                    print("-" * 50)
                else:
                    print(f"Level         : NO TRAFFIC")
                    print("-" * 50)
                
                last_eval = current_time
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
        process.terminate()
        save_monitoring_plots(history)

def save_monitoring_plots(history):
    if not history:
        print("No monitoring history to plot.")
        return
    
    steps = [h["step"] for h in history]
    scores = [h["anomaly_score"] for h in history]
    base_thresholds = [h["base_threshold"] for h in history]
    ext_thresholds = [h["ext_threshold"] for h in history]
    levels = [h["level"] for h in history]

    # 1. Threshold only graph
    plt.figure()
    plt.plot(steps, base_thresholds, label="Base Threshold")
    plt.plot(steps, ext_thresholds, label="Extreme Threshold")
    plt.xlabel("Window Step")
    plt.ylabel("Threshold Value")
    plt.title("Adaptive Threshold Over Time")
    plt.legend()
    plt.tight_layout()
    plt.savefig("threshold_over_time.png", dpi=300)
    plt.close()

    # 2. Anomaly score over time
    plt.figure()
    plt.plot(steps, scores, label="Anomaly Score")
    plt.plot(steps, base_thresholds, linestyle="--", label="Base Threshold")
    plt.plot(steps, ext_thresholds, linestyle="--", label="Extreme Threshold")
    plt.xlabel("Window Step")
    plt.ylabel("Anomaly Score")
    plt.title("Anomaly Score Over Time")
    plt.legend()
    plt.tight_layout()
    plt.savefig("anomaly_score_over_time.png", dpi=300)
    plt.close()

    # 3. Level count bar chart
    level_order = ["NORMAL", "SUSPICIOUS", "ATTACK"]
    counts = [levels.count(level) for level in level_order]

    plt.figure()
    plt.bar(level_order, counts)
    plt.xlabel("Detection Level")
    plt.ylabel("Count")
    plt.title("Detection Level Counts")
    plt.tight_layout()
    plt.savefig("level_count_bar_chart.png", dpi=300)
    plt.close()

    print("Saved")