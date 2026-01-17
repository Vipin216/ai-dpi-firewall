import csv
import pandas as pd
from sklearn.ensemble import IsolationForest

INPUT_FILE = "data/features.csv"
OUTPUT_FILE = "data/ai_scores.csv"


df = pd.read_csv(INPUT_FILE)

feature_cols = [
    "packet_count",
    "unique_src_ips",
    "unique_dst_ips",
    "http_requests",
    "dns_queries",
    "syn_packets"
]

X = df[feature_cols]


model = IsolationForest(
    n_estimators=100,
    contamination=0.1,   
    random_state=42
)

model.fit(X)


df["anomaly_score"] = model.decision_function(X)
df["is_anomaly"] = model.predict(X)


df["ai_risk"] = (1 - (df["anomaly_score"] - df["anomaly_score"].min())
                 / (df["anomaly_score"].max() - df["anomaly_score"].min())) * 100


df[["window_start", "ai_risk", "is_anomaly"]].to_csv(OUTPUT_FILE, index=False)

print("AI anomaly detection complete → data/ai_scores.csv")
