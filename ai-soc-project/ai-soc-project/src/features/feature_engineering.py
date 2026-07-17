"""
Feature engineering for the AI-SOC detection pipeline.

Takes raw normalized events (the schema produced by data/generate_sample_logs.py,
which mirrors what you'd get after parsing Wazuh/Winlogbeat output) and rolls
them up into fixed-size windows per (host, src_ip) pair. Each window becomes
one row of numeric features fed to the ML model.

Why windowed features instead of raw events: almost every attack pattern here
(brute force, port scan, beaconing, exfil) is only visible as a *pattern over
time*, not from any single event. A single failed login is normal; forty in
sixty seconds is a brute force.
"""

import pandas as pd
import numpy as np


WINDOW = "1min"


def load_events(csv_path):
    df = pd.read_csv(csv_path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0)
    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df = df.sort_values("timestamp")
    df = df[(df["host"].astype(bool)) & (df["src_ip"].notna()) & (df["src_ip"] != "")]

    # Bucket into fixed windows per (host, src_ip). Using groupby with a
    # Grouper (rather than .resample()) only materializes buckets that
    # actually contain events, instead of densely filling every minute
    # across each group's full time span -- with sparse external-IP traffic
    # spread over several days, resample() would blow up into millions of
    # empty rows.
    grouped = df.groupby(
        ["host", "src_ip", pd.Grouper(key="timestamp", freq=WINDOW)],
        dropna=False,
    )

    out = grouped.agg(
        event_count=("event_type", "size"),
        failed_login_count=("status", lambda x: (x == "failed").sum()),
        distinct_dst_ports=("dst_port", "nunique"),
        distinct_dst_ips=("dst_ip", "nunique"),
        distinct_users=("user", "nunique"),
        total_bytes_out=("bytes_out", "sum"),
        max_bytes_out=("bytes_out", "max"),
        attack_present=("is_attack", "max"),
    ).reset_index()

    out = out[out["event_count"] > 0]
    out["hour"] = out["timestamp"].dt.hour
    out["is_weekday"] = (out["timestamp"].dt.dayofweek < 5).astype(int)
    out = out.fillna(0)
    return out


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


if __name__ == "__main__":
    import sys
    from pathlib import Path

    src = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parents[2] / "data" / "sample_logs.csv")
    out_path = Path(__file__).resolve().parents[2] / "data" / "features.csv"

    events = load_events(src)
    features = build_features(events)
    features.to_csv(out_path, index=False)
    print(f"Built {len(features)} feature rows from {len(events)} events -> {out_path}")
    print(f"Windows containing attack activity: {int(features['attack_present'].sum())}")
