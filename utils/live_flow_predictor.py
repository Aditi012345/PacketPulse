from scapy.all import sniff
import os
import pandas as pd

from cicids_flow_features import extract_flow_features, FEATURE_COLUMNS
from model_loader import load_model
from predictions import predict_with_model

MODEL_PATH = os.path.join("..", "models", "cicids_xgboost.pkl")
CAPTURE_SECONDS = 10

iface = os.getenv("ifaces")

print("\nTesting interface:", iface)
print(f"Generate traffic now (browse / ping google.com). Capturing for {CAPTURE_SECONDS} seconds...\n")

pkts = sniff(iface=iface, timeout=CAPTURE_SECONDS, store=True, filter="ip")
print("Captured packets:", len(pkts))

to_show = pkts[:10]
print(f"\nShowing first {len(to_show)} packet heading(s):")
for i, pkt in enumerate(to_show, start=1):
    print(f"  {i}. {pkt.summary()}")

rows = extract_flow_features(pkts)
df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
print(f"\nReconstructed flows: {len(df)}")

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
    print("\nPer-flow predictions:\n")
    print(scored.to_string(index=False))
