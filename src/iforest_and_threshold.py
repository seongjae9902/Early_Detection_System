import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = ["packet_count", "total_bytes", "avg_bytes", "iat_mean"]

def iforest(csv_path, output_csv_path):
    # Load CSV
    df = pd.read_csv(csv_path)

    # Select Features
    X = df[FEATURES]

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators = 100,
        contamination = "auto",
        random_state = 42
    )
    model.fit(X)

    # Compute anomaly score
    # Reverse score to show that high score == abnormality
    df["anomaly_score"] = -model.decision_function(X)

    # Compute thresholds
    # Top 5% is a little doubted
    # Top 0.5% is considered as anomaly
    base_threshold = df["anomaly_score"].quantile(0.95)
    ext_threshold = df["anomaly_score"].quantile(0.995)

    # Print results
    print("=====Isolation Forest Results=====")
    print(f"Total Windows              : {len(df)}")
    print(f"Base threshold (0.95)      : {base_threshold:.6f}")
    print(f"Extreme threshold (0.995)  : {ext_threshold:.6f}")

    # Save scored data
    if output_csv_path is not None:
        df.to_csv(output_csv_path, index=False)

    return model, base_threshold, ext_threshold, df