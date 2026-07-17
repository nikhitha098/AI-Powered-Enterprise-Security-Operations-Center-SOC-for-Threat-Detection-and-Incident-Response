"""
Detection engine.

Loads the trained models and scores a features dataframe, producing an
`alerts.json` of flagged windows. A window is flagged if EITHER model
thinks it's suspicious:

  - Isolation Forest anomaly score above threshold (unsupervised signal)
  - Random Forest attack probability above threshold (supervised signal)

Combining both means a genuinely novel attack pattern the classifier has
never seen a similar example of can still be caught by the anomaly detector,
while the classifier sharpens precision on patterns it recognizes.

Run standalone: python3 src/models/detect.py [features_csv]
"""

import json
import sys
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT / "src" / "models" / "artifacts"
ALERTS_PATH = ROOT / "data" / "alerts.json"

FEATURE_COLUMNS = [
    "event_count",
    "failed_login_count",
    "distinct_dst_ports",
    "distinct_dst_ips",
    "distinct_users",
    "total_bytes_out",
    "max_bytes_out",
    "hour",
    "is_weekday",
]

RF_THRESHOLD = 0.5
ISO_ANOMALY_THRESHOLD = 0  # sklearn's own -1/1 decision boundary


def load_models():
    iso = joblib.load(MODELS_DIR / "isolation_forest.pkl")
    rf = joblib.load(MODELS_DIR / "random_forest.pkl")
    scaler = joblib.load(MODELS_DIR / "scaler.pkl")
    return iso, rf, scaler


def score(df: pd.DataFrame) -> pd.DataFrame:
    iso, rf, scaler = load_models()
    X = df[FEATURE_COLUMNS].fillna(0)
    X_scaled = scaler.transform(X)

    iso_flag = (iso.predict(X_scaled) == -1)
    iso_score = -iso.score_samples(X_scaled)
    rf_proba = rf.predict_proba(X_scaled)[:, 1]
    rf_flag = rf_proba >= RF_THRESHOLD

    out = df.copy()
    out["iso_anomaly_score"] = iso_score
    out["iso_flag"] = iso_flag
    out["rf_attack_proba"] = rf_proba
    out["rf_flag"] = rf_flag
    out["flagged"] = iso_flag | rf_flag

    # simple severity heuristic combining both signals
    out["severity"] = "low"
    out.loc[(out["rf_flag"]) & (out["iso_flag"]), "severity"] = "high"
    out.loc[(out["rf_flag"]) & (~out["iso_flag"]), "severity"] = "medium"
    out.loc[(~out["rf_flag"]) & (out["iso_flag"]), "severity"] = "medium"
    return out


def to_alerts(scored: pd.DataFrame) -> list:
    flagged = scored[scored["flagged"]].copy()
    flagged = flagged.sort_values("rf_attack_proba", ascending=False)
    alerts = []
    for _, row in flagged.iterrows():
        alerts.append({
            "timestamp": str(row["timestamp"]),
            "host": row["host"],
            "src_ip": row["src_ip"],
            "severity": row["severity"],
            "rf_attack_probability": round(float(row["rf_attack_proba"]), 3),
            "iso_anomaly_score": round(float(row["iso_anomaly_score"]), 3),
            "event_count": int(row["event_count"]),
            "failed_login_count": int(row["failed_login_count"]),
            "distinct_dst_ports": int(row["distinct_dst_ports"]),
            "distinct_dst_ips": int(row["distinct_dst_ips"]),
            "total_bytes_out": float(row["total_bytes_out"]),
            "true_label": int(row.get("attack_present", 0)),
        })
    return alerts


def main():
    features_csv = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "data" / "features.csv")
    df = pd.read_csv(features_csv)
    scored = score(df)
    alerts = to_alerts(scored)

    with open(ALERTS_PATH, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"Scored {len(df)} windows -> {len(alerts)} alerts flagged -> {ALERTS_PATH}")
    sev_counts = {}
    for a in alerts:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1
    print("Severity breakdown:", sev_counts)


if __name__ == "__main__":
    main()
