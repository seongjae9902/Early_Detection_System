from extract_features import extract_features

FEATURES = ["packet_count", "total_bytes", "avg_bytes", "iat_mean"]

def scoring(pcap_path, window_size, model):
    df = extract_features(pcap_path, None, window_size)

    if df.empty:
        print("No features extracted")
        return df

    X = df[FEATURES]
    df["anomaly_score"] = -model.decision_function(X)

    return df