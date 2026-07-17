"""
SOAR (Security Orchestration, Automation, and Response) playbook engine.

Applies rule-based response actions to enriched alerts. In a production
deployment these actions would call real APIs (EDR isolate-host, firewall
block-IP, IAM disable-user, ticketing system create-issue). Here each action
is *simulated* -- it's logged as if it happened, with the exact API call that
would be made in a real deployment shown in `simulated_call`, so the project
demonstrates the full decision logic safely without touching real
infrastructure.

Swapping a simulated action for a real one is meant to be a small, isolated
change: replace the body of the corresponding `action_*` function with a
real `requests.post(...)` to your firewall/EDR/ticketing API.

Playbooks:
  A. Suspicious login (brute force pattern + high severity)
       -> disable user account, open ticket, notify analyst
  B. Malware / C2 indicator (known-bad IP + high severity)
       -> isolate host, open ticket, notify analyst
  C. Port scan / recon (medium+ severity, many distinct ports)
       -> block source IP at firewall for a cooldown window, log only
"""

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENRICHED_PATH = ROOT / "data" / "alerts_enriched.json"
ACTIONS_LOG_PATH = ROOT / "data" / "response_actions.json"

BLOCK_COOLDOWN_MINUTES = 60


def action_disable_user(alert):
    return {
        "action": "disable_user_account",
        "target": alert.get("host"),
        "simulated_call": "IAM.disable_account(host=..., reason='brute_force_detected')",
        "status": "simulated_success",
    }


def action_isolate_host(alert):
    return {
        "action": "isolate_host",
        "target": alert["host"],
        "simulated_call": f"EDR.isolate(host='{alert['host']}')  # e.g. Wazuh active-response firewall-drop",
        "status": "simulated_success",
    }


def action_block_ip(alert):
    return {
        "action": "block_source_ip",
        "target": alert["src_ip"],
        "duration_minutes": BLOCK_COOLDOWN_MINUTES,
        "simulated_call": f"Firewall.block(ip='{alert['src_ip']}', minutes={BLOCK_COOLDOWN_MINUTES})",
        "status": "simulated_success",
    }


def action_create_ticket(alert, summary):
    return {
        "action": "create_ticket",
        "simulated_call": f"Ticketing.create(title='{summary}', severity='{alert['severity']}')",
        "status": "simulated_success",
    }


def action_notify_analyst(alert, summary):
    return {
        "action": "notify_analyst",
        "simulated_call": f"Slack.post_message(channel='#soc-alerts', text='{summary}')",
        "status": "simulated_success",
    }


def classify_playbook(alert):
    """Decide which playbook applies based on the alert's features."""
    if alert["failed_login_count"] >= 5 and alert["severity"] in ("high", "medium"):
        return "A_suspicious_login"
    if alert["threat_intel"]["is_known_bad"] and alert["severity"] == "high":
        return "B_malware_c2"
    if alert["distinct_dst_ports"] >= 10:
        return "C_port_scan"
    return None


def run_playbook(alert):
    playbook = classify_playbook(alert)
    actions = []

    if playbook == "A_suspicious_login":
        summary = f"Suspicious login pattern on {alert['host']} from {alert['src_ip']} ({alert['failed_login_count']} failed attempts)"
        actions.append(action_disable_user(alert))
        actions.append(action_create_ticket(alert, summary))
        actions.append(action_notify_analyst(alert, summary))

    elif playbook == "B_malware_c2":
        summary = f"Known-bad indicator matched on {alert['host']} (src {alert['src_ip']}) -- possible malware/C2"
        actions.append(action_isolate_host(alert))
        actions.append(action_create_ticket(alert, summary))
        actions.append(action_notify_analyst(alert, summary))

    elif playbook == "C_port_scan":
        summary = f"Port scan detected from {alert['src_ip']} against {alert['host']} ({alert['distinct_dst_ports']} ports)"
        actions.append(action_block_ip(alert))
        actions.append(action_create_ticket(alert, summary))

    return {
        "alert_timestamp": alert["timestamp"],
        "host": alert["host"],
        "src_ip": alert["src_ip"],
        "severity": alert["severity"],
        "playbook_triggered": playbook,
        "actions": actions,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }


def main():
    with open(ENRICHED_PATH) as f:
        alerts = json.load(f)

    results = []
    for alert in alerts:
        result = run_playbook(alert)
        if result["playbook_triggered"]:
            results.append(result)

    with open(ACTIONS_LOG_PATH, "w") as f:
        json.dump(results, f, indent=2)

    counts = {}
    for r in results:
        counts[r["playbook_triggered"]] = counts.get(r["playbook_triggered"], 0) + 1

    print(f"Evaluated {len(alerts)} alerts, triggered {len(results)} playbook runs.")
    print("Breakdown:", counts)
    print(f"Wrote {ACTIONS_LOG_PATH}")


if __name__ == "__main__":
    main()
