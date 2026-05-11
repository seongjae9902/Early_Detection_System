from collections import deque
import subprocess
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import select
from pathlib import Path

FEATURES = [
    "packet_count",
    "total_bytes",
    "avg_bytes",
    "iat_mean",
    "unique_dst_ip",
    "unique_dst_port"
]

def compute_features(buffer):
    if not buffer:
        return None
    
    times = [x[0] for x in buffer]
    sizes = [x[1] for x in buffer]
    dst_ips = [x[2] for x in buffer]
    dst_ports = [x[3] for x in buffer]

    packet_count = len(sizes)
    total_bytes = sum(sizes)
    avg_bytes = total_bytes / packet_count if packet_count > 0 else 0
    unique_dst_ip = len(set(ip for ip in dst_ips if ip != ""))
    unique_dst_port = len(set(port for port in dst_ports if port != ""))

    if len(times) > 1:
        iats = np.diff(times)
        iat_mean = float(np.mean(iats))
    else:
        iat_mean = 0.0
    
    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_bytes": avg_bytes,
        "iat_mean": iat_mean,
        "unique_dst_ip": unique_dst_ip,
        "unique_dst_port": unique_dst_port
    }

def classify_score(high_risk, is_suspicious):
    if high_risk:
        return "ATTACK"
    elif is_suspicious:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

def monitor(interface, model, base_threshold, ext_threshold, window_size=5, step_size=1):
    recent_scores = deque(maxlen=30)
    risk_window = deque(maxlen=10)

    phase_steps = {"NORMAL": 0}
    pending_phase = None

    consecutive_suspicious = 0
    Persistence_threshold = 60
    Min_Base_Threshold = 0.08
    Small_Margin = 0.005
    Adapt_Suspicious_Limit = 5
    Adapt_Max_Score_Ratio = 0.5 * (ext_threshold - base_threshold)
    adapt_score_limit = base_threshold + Adapt_Max_Score_Ratio

    history = []
    step_count = 0
    
    buffer = deque()
    last_eval = time.time()

    cmd = [
        "sudo",
        "tshark",
        "-i", interface,
        "-l",
        "-n",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport"
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("==== Real-Time Monitoring Started ====")
    print(f"Interface   : {interface}")
    print(f"Window Size : {window_size} sec")
    print(f"Step Size   : {step_size} sec")
    print("-" * 50)

    try:
        while True:
            line = ""

            ready, _, _ = select.select([process.stdout], [], [], 0.1)
            if ready:
                line = process.stdout.readline().rstrip("\n")
            #print("RAW:", repr(line))

            if line:
                parts = line.split("\t")
                if len(parts) >= 2:
                    try:
                        pkt_time = time.time()
                        pkt_size = int(parts[1])
                        dst_ip = parts[2] if len(parts) > 2 else ""
                        tcp_port = parts[3] if len(parts) > 3 else ""
                        udp_port = parts[4] if len(parts) > 4 else ""
                        dst_port = tcp_port if tcp_port else udp_port

                        marker_ports = {
                            "7772": "DRIFT",
                            "7773": "BEACON",
                            "7774": "BURST"
                        }

                        if dst_port in marker_ports:
                            pending_phase = marker_ports[dst_port]
                            continue

                        buffer.append((pkt_time, pkt_size, dst_ip, dst_port))
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
                current_step = step_count

                if pending_phase is not None and pending_phase not in phase_steps:
                    phase_steps[pending_phase] = current_step
                    pending_phase = None
                
                feat = compute_features(buffer)

                if feat is not None:
                    X = pd.DataFrame([feat])[FEATURES]
                    score = -model.decision_function(X)[0]

                    is_suspicious = score > (base_threshold + Small_Margin)
                    is_extreme = score > ext_threshold

                    if is_suspicious:
                        consecutive_suspicious += 1
                    else:
                        consecutive_suspicious = 0
                    
                    high_risk = is_extreme or (consecutive_suspicious >= Persistence_threshold)

                    level = classify_score(high_risk, is_suspicious)

                    if (
                        not high_risk
                        and score < adapt_score_limit
                        and consecutive_suspicious <= Adapt_Suspicious_Limit
                    ):
                        recent_scores.append(score)
                    
                    if not high_risk and len(recent_scores) >= 30:
                        recent_p95 = np.percentile(list(recent_scores), 95)
                        base_threshold = max(
                            Min_Base_Threshold,
                            0.8 * base_threshold + 0.2 * recent_p95
                        )

                    history.append({
                        "step": current_step,
                        "packet_count": feat["packet_count"],
                        "total_bytes": feat["total_bytes"],
                        "avg_bytes": feat["avg_bytes"],
                        "iat_mean": feat["iat_mean"],
                        "unique_dst_ip": feat["unique_dst_ip"],
                        "unique_dst_port": feat["unique_dst_port"],
                        "anomaly_score": score,
                        "base_threshold": base_threshold,
                        "ext_threshold": ext_threshold,
                        "level": level,
                        "high_risk": high_risk,
                        "consecutive_suspicious": consecutive_suspicious,
                        "is_extreme": is_extreme
                    })

                    print(f"Steps          : {current_step}")
                    print(f"Level          : {level}")
                    print(f"Packet Count   : {feat['packet_count']}")
                    print(f"Total Bytes    : {feat['total_bytes']} bytes")
                    print(f"Avg Packet     : {feat['avg_bytes']:.2f} bytes")
                    print(f"IAT Mean       : {feat['iat_mean']:.4f} sec")
                    print(f"Anomaly Score  : {score:.6f}")
                    print(f"Base Threshold : {base_threshold:.6f}")
                    print(f"Extreme Thresh : {ext_threshold:.6f}")
                    print(f"Conse Susp     : {consecutive_suspicious}")
                    print(f"High Risk      : {high_risk}")
                    print("-" * 50)
                else:
                    print(f"Level         : NO TRAFFIC")
                    print("-" * 50)
                
                step_count += 1
                last_eval = current_time
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
        process.terminate()
        save_monitoring_plots(history, phase_steps)

def save_monitoring_plots(history, phase_steps):
    if not history:
        print("No monitoring history to plot.")
        return
    
    BASE_DIR = Path(__file__).resolve().parent.parent
    RESULT_DIR = BASE_DIR / "results"
    RESULT_DIR.mkdir(exist_ok=True)

    df = pd.DataFrame(history)
    df.to_csv(RESULT_DIR / "monitor_history.csv", index=False)

    steps = [h["step"] for h in history]
    scores = [h["anomaly_score"] for h in history]
    base_thresholds = [h["base_threshold"] for h in history]
    ext_thresholds = [h["ext_threshold"] for h in history]
    levels = [h["level"] for h in history]

    # 1. Threshold only graph
    plt.figure()
    for label, x in phase_steps.items():
        plt.axvline(x=x, linestyle=":", linewidth=1)
        text_x = x + 3 if x == 0 else x + 3
        plt.text(x, max(scores), label, rotation=90, verticalalignment="top")
    plt.plot(steps, base_thresholds, label="Base Threshold")
    plt.plot(steps, ext_thresholds, label="Extreme Threshold")
    plt.xlabel("Window Step")
    plt.ylabel("Threshold Value")
    plt.title("Adaptive Threshold Over Time")
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULT_DIR / "threshold_over_time.png", dpi=300)
    plt.close()

    # 2. Anomaly score over time
    plt.figure()
    for label, x in phase_steps.items():
        plt.axvline(x=x, linestyle=":", linewidth=1)
        text_x = x + 3 if x == 0 else x + 3
        plt.text(x, max(scores), label, rotation=90, verticalalignment="top")
    plt.plot(steps, scores, label="Anomaly Score")
    plt.plot(steps, base_thresholds, linestyle="--", label="Base Threshold")
    plt.plot(steps, ext_thresholds, linestyle="--", label="Extreme Threshold")
    plt.xlabel("Window Step")
    plt.ylabel("Anomaly Score")
    plt.title("Anomaly Score Over Time")
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULT_DIR / "anomaly_score_over_time.png", dpi=300)
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
    plt.savefig(RESULT_DIR / "level_count_bar_chart.png", dpi=300)
    plt.close()

    # 4. Level over time
    level_map = {"NORMAL": 0, "SUSPICIOUS": 1, "ATTACK": 2}
    level_values = [level_map[level] for level in levels]

    plt.figure()
    plt.plot(steps, level_values)
    plt.yticks([0, 1, 2], ["NORMAL", "SUSPICIOUS", "ATTACK"])
    plt.xlabel("Window Step")
    plt.ylabel("Detection Level")
    plt.title("Detection Level Over Time")

    for label, x in phase_steps.items():
        plt.axvline(x=x, linestyle=":", linewidth=1)
        plt.text(x, 2, label, rotation=90, verticalalignment="top")

    plt.tight_layout()
    plt.savefig(RESULT_DIR / "detection_level_over_time.png", dpi=300)
    plt.close()

    print("Saved")
