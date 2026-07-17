"""
AI-SOC analyst dashboard.

A lightweight Flask app that reads the pipeline's output files (alerts,
enriched alerts, response actions, model metrics) and renders an overview
dashboard: alert volume, severity breakdown, top offending IPs, and a live
feed of triggered SOAR playbooks. This is the "human in the loop" surface
of the project -- in a real deployment this would be Kibana/Grafana panels
pulling from the SIEM index; here it reads directly from the JSON artifacts
the pipeline produces so the whole thing runs with zero external services.

Run:
    python3 src/dashboard/app.py
Then open http://localhost:5000
"""

import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"

app = Flask(__name__)


def load_json(path, default):
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return default


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    alerts = load_json(DATA_DIR / "alerts_enriched.json", [])
    actions = load_json(DATA_DIR / "response_actions.json", [])
    metrics_path = ROOT / "src" / "models" / "artifacts" / "metrics.json"
    metrics = load_json(metrics_path, {})

    severity_counts = Counter(a["severity"] for a in alerts)
    top_ips = Counter(a["src_ip"] for a in alerts).most_common(10)
    top_hosts = Counter(a["host"] for a in alerts).most_common(10)
    known_bad = sum(1 for a in alerts if a["threat_intel"]["is_known_bad"])

    playbook_counts = Counter(a["playbook_triggered"] for a in actions if a["playbook_triggered"])

    true_positives = sum(1 for a in alerts if a.get("true_label") == 1)
    false_positives = sum(1 for a in alerts if a.get("true_label") == 0)

    return jsonify({
        "total_alerts": len(alerts),
        "severity_counts": dict(severity_counts),
        "top_ips": top_ips,
        "top_hosts": top_hosts,
        "known_bad_matches": known_bad,
        "playbook_counts": dict(playbook_counts),
        "total_response_actions": sum(len(a["actions"]) for a in actions),
        "model_metrics": metrics,
        "true_positive_alerts": true_positives,
        "false_positive_alerts": false_positives,
    })


@app.route("/api/alerts")
def api_alerts():
    alerts = load_json(DATA_DIR / "alerts_enriched.json", [])
    alerts_sorted = sorted(alerts, key=lambda a: a["rf_attack_probability"], reverse=True)
    return jsonify(alerts_sorted[:100])


@app.route("/api/actions")
def api_actions():
    actions = load_json(DATA_DIR / "response_actions.json", [])
    return jsonify(actions[:100])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
