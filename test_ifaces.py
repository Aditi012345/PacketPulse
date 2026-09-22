from scapy.all import sniff
import os
import pandas as pd

from utils.cicids_flow_features import extract_flow_features, FEATURE_COLUMNS

iface = os.getenv("ifaces")

print("\nTesting interface:", iface)
print("Generate traffic now (open YouTube / ping google.com). Capturing for 10 seconds...\n")

pkts = sniff(iface=iface, timeout=10, store=True, filter="ip")
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
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", None)
    print("\nCICIDS flow metrics (first 10 flows):\n")
    print(df.head(10).to_string(index=False))
