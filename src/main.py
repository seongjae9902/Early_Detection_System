from extract_features import extract_features
from iforest_and_threshold import iforest
from monitor import monitor

def main():
    baseline_pcap = "baseline_train.pcap"
    features_csv = "baseline_train_features.csv"
    scored_csv = "baseline_scored.csv"
    window_size = 5
    interface = "enp0s8"

    print("Step 1: Extract baseline features")
    extract_features(baseline_pcap, features_csv, window_size)

    print("Step 2: Train model and calculate thresholds")
    model, base_threshold, ext_threshold, _ = iforest(features_csv, scored_csv)

    print("Step 3: Start real-time monitoring")
    monitor(
        interface=interface,
        model=model,
        base_threshold=base_threshold,
        ext_threshold=ext_threshold,
        window_size=5,
        step_size=1
    )

if __name__ == "__main__":
    main()