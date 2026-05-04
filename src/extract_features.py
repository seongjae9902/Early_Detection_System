import subprocess
import pandas as pd

def extract_features(pcap_path, output_csv_path, window_size):
    # -------------------
    # Using 'tshark' to parse raw data
    # Then, extract the time and size of each packets
    # -------------------
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len"
    ]


    # -------------------
    # Get lines from results
    # then, compute time and size of each line
    # append fairs of each after casting to float/int
    # -------------------
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    lines = result.stdout.strip().split("\n")

    data = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) == 2:
            try:
                t = float(parts[0])
                size = int(parts[1])
                data.append((t, size))
            except ValueError:
                pass

    if len(data) == 0:
        features = pd.DataFrame(columns=[
            "packet_count", "total_bytes", "avg_bytes", "iat_mean"
        ])
        if output_csv_path is not None:
            features.to_csv(output_csv_path, index=False)
        return features
    
    df = pd.DataFrame(data, columns=["time", "size"])
    df = df.sort_values("time")

    start_time = df["time"].min()
    end_time = df["time"].max()

    windows = []
    current = start_time

    while current < end_time:
        window_df = df[(df["time"] >= current) & (df["time"] < current + window_size)]

        if len(window_df) > 0:
            packet_count = len(window_df)
            total_bytes = window_df["size"].sum()
            avg_bytes = window_df["size"].mean()
            iat = window_df["time"].diff().dropna()
            iat_mean = iat.mean() if len(iat) > 0 else 0

            windows.append([packet_count, total_bytes, avg_bytes, iat_mean])

        current += window_size

    features = pd.DataFrame(windows, columns=[
        "packet_count", "total_bytes", "avg_bytes", "iat_mean"
    ])

    if output_csv_path is not None:
        features.to_csv(output_csv_path, index=False)

    return features