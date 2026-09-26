from scapy.all import sniff
import os
import pandas as pd

from .cicids_flow_features import extract_flow_features, FEATURE_COLUMNS
from .model_loader import load_model
from .predictions import predict_with_model

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  
MODEL_PATH = os.path.join(BASE_DIR, "models", "cicids_xgboost.pkl")


def run_capture_and_predict(capture_seconds=10):
    iface = os.getenv("ifaces")
    print(f"Generate traffic now (browse / ping google.com). Capturing for {capture_seconds} seconds...\n")

    pkts = sniff(iface=iface, timeout=capture_seconds, store=True, filter="ip")
    print("Captured packets:", len(pkts))

    rows = extract_flow_features(pkts)
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    print(f"\nReconstructed flows: {len(df)}")

    n_packets = len(pkts)
    n_flows = len(df)
    n_benign = 0
    n_threat = 0

    if df.empty:
        print("No IP flows to score. Generate traffic and try again.")
    else:
        model = load_model(MODEL_PATH)
        X = df[FEATURE_COLUMNS].fillna(0)
        preds = predict_with_model(model, X)
        threat_scores = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else preds

        scored = df[["Destination Port"]].copy()
        scored["prediction"] = preds
        scored["threat_probability"] = threat_scores
        scored["verdict"] = scored["prediction"].map({0: "BENIGN", 1: "THREAT"})

        n_threat = int((scored["prediction"] == 1).sum())
        n_benign = int((scored["prediction"] == 0).sum())
        print(f"\nXGBoost verdicts: {n_benign} BENIGN, {n_threat} THREAT (of {len(scored)} flows)")

    return n_packets, n_flows, n_benign, n_threat

