# Early-Stage Intrusion Detection using Isolation Forest

## Overview

This project implements an early-stage intrusion detection pipeline using machine learning and network traffic analysis. The goal is to identify stealthy or suspicious network access behavior before it becomes a full-scale attack.
The system extracts statistical traffic features from PCAP files using TShark, processes the extracted data with Python, and applies an Isolation Forest model to detect anomalous network activity. The project also includes sliding-window analysis and adaptive threshold logic to support early detection under changing traffic conditions.

## Motivation

Traditional intrusion detection often focuses on known attack signatures or obvious malicious behavior. This project explores whether early-stage access patterns can be detected using statistical network features and unsupervised anomaly detection.
The main focus is not only model prediction, but also building a repeatable detection workflow that includes feature extraction, preprocessing, thresholding, and evaluation.

## Tech Stack
- Python
- Scikit-learn
- Pandas
- NumPy
- TShark
- PCAP network traffic data
- Isolation Forest

## Key Features
- Extracted traffic features from PCAP files using TShark
- Built a Python-based preprocessing pipeline for network traffic analysis
- Implemented an Isolation Forest model for anomaly detection
- Applied sliding-window analysis to observe short-term traffic behavior
- Used adaptive threshold logic to reduce static-threshold limitations
- Evaluated traffic patterns using statistical features such as:
  - Flow count
  - Packet count
  - Byte count
  - Interarrival timing
  - Unique destination IP count
  - Unique destination port count
  - Flow duration

## Workflow
1. Load PCAP network traffic data
2. Extract statistical traffic features using TShark
3. Clean and preprocess extracted feature data
4. Apply sliding-window analysis over traffic sequences
5. Train or apply an Isolation Forest model
6. Generate anomaly scores for suspicious behavior
7. Compare anomaly scores against adaptive thresholds
8. Review detected events and analyze model behavior

## Results

The system was able to identify unusual traffic patterns by combining statistical feature extraction with unsupervised anomaly detection. The sliding-window and adaptive threshold components helped make the detection logic more flexible compared with a fixed-threshold approach.
