"""
Basic tests for the AI-SOC pipeline. These exercise the real logic against
small in-memory data rather than mocking everything, so a broken feature
calculation or a broken playbook rule actually gets caught.

Run with: pytest -q
"""

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.features.feature_engineering import build_features, FEATURE_COLUMNS
from src.soar.playbooks import classify_playbook


def make_event(**overrides):
    base = {
        "timestamp": "2026-06-01T10:00:00",
        "event_type": "login",
        "host": "host-01",
        "user": "user01",
        "src_ip": "10.0.0.5",
        "dst_ip": "",
        "dst_port": "",
        "status": "success",
        "bytes_out": 0,
        "is_attack": 0,
        "attack_type": "",
    }
    base.update(overrides)
    return base


def test_feature_engineering_detects_failed_logins():
    events = [make_event(status="failed") for _ in range(5)]
    events += [make_event(status="success")]
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    features = build_features(df)
    assert not features.empty
    row = features.iloc[0]
    assert row["failed_login_count"] == 5
    assert row["event_count"] == 6
    for col in FEATURE_COLUMNS:
        assert col in features.columns


def test_feature_engineering_handles_empty_input():
    df = pd.DataFrame(columns=[
        "timestamp", "event_type", "host", "user", "src_ip", "dst_ip",
        "dst_port", "status", "bytes_out", "is_attack", "attack_type",
    ])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    features = build_features(df)
    assert features.empty


@pytest.mark.parametrize("failed_logins,severity,expected", [
    (10, "high", "A_suspicious_login"),
    (0, "medium", None),
])
def test_playbook_classification_login(failed_logins, severity, expected):
    alert = {
        "failed_login_count": failed_logins,
        "severity": severity,
        "distinct_dst_ports": 1,
        "threat_intel": {"is_known_bad": False},
    }
    assert classify_playbook(alert) == expected


def test_playbook_classification_port_scan():
    alert = {
        "failed_login_count": 0,
        "severity": "medium",
        "distinct_dst_ports": 25,
        "threat_intel": {"is_known_bad": False},
    }
    assert classify_playbook(alert) == "C_port_scan"


def test_playbook_classification_malware_c2():
    alert = {
        "failed_login_count": 0,
        "severity": "high",
        "distinct_dst_ports": 1,
        "threat_intel": {"is_known_bad": True},
    }
    assert classify_playbook(alert) == "B_malware_c2"
