[ai_powered_soc_project_guide.md](https://github.com/user-attachments/files/30113123/ai_powered_soc_project_guide.md)
# AI-Powered Enterprise SOC — Step-by-Step Build Guide

A Security Operations Center that ingests logs from across an enterprise, uses machine learning to flag anomalous or malicious activity, enriches alerts with threat intelligence, and automates parts of incident response. This guide walks through the whole build, from lab setup to a working demo you can present.

---

## Phase 0 — Define scope and success criteria

Before touching tools, pin down what "done" looks like. Suggested scope for a solo/small-team project (2–3 months):

- **In scope:** a home-lab or cloud sandbox network generating logs, a SIEM to collect them, one or two ML models for anomaly/threat detection, a rules + AI-scored alert pipeline, basic SOAR playbooks (isolate host, block IP, open ticket), and a dashboard.
- **Out of scope (mention as "future work"):** full UEBA across thousands of users, production-grade high availability, compliance certification.
- **Success metrics to report at the end:** detection precision/recall on a labeled test set, mean time to detect (MTTD), mean time to respond (MTTR) with vs without automation, false positive rate.

Deliverables to plan for: architecture diagram, working pipeline, a short report, and a live/recorded demo of an attack being detected and auto-contained.

---

## Phase 1 — Architecture

Five layers, shown in the diagram above:

1. **Log sources** — endpoints, network devices, cloud services.
2. **SIEM ingestion** — collects, parses, normalizes, indexes logs.
3. **AI detection engine** — scores events for anomalies/threats.
4. **Threat intel enrichment** — adds context (known-bad IPs, hashes, domains).
5. **SOAR automation → Analyst dashboard** — triggers response actions and surfaces everything for a human analyst.

### Recommended tech stack (all free/open-source, good for a portfolio project)

| Layer | Tool options | Pick for this guide |
|---|---|---|
| Log generation / lab | VMs, Docker containers, Kali attacker box | VirtualBox/VMware + Docker |
| Log shipping | Filebeat, Winlogbeat, Fluentd | Filebeat/Winlogbeat |
| SIEM | Wazuh, ELK (Elasticsearch/Logstash/Kibana), Splunk Free | **Wazuh** (built-in agents, free, security-focused) |
| ML/anomaly detection | scikit-learn, PyOTX, TensorFlow | scikit-learn (Isolation Forest, One-Class SVM) + a simple autoencoder |
| Threat intel | MISP, VirusTotal API, AbuseIPDB | VirusTotal + AbuseIPDB APIs (free tiers) |
| SOAR | TheHive + Cortex, Shuffle, StackStorm | Shuffle (free, no-code, easy to demo) or TheHive/Cortex |
| Dashboard | Kibana, Grafana | Kibana (bundled with Wazuh) + optional Grafana |
| Attack simulation | Atomic Red Team, Caldera, Metasploit | Atomic Red Team (safe, scoped tests) |

---

## Phase 2 — Build the lab environment

1. **Host machine:** needs 16GB+ RAM ideally (Wazuh + Elastic stack are memory-hungry).
2. **Set up VMs/containers:**
   - 1x Wazuh manager (Ubuntu 22.04, 4GB+ RAM) — via Docker or native install.
   - 2–3x "victim" endpoints (1 Windows 10/11, 1–2 Ubuntu) with Wazuh agents installed.
   - 1x "attacker" machine (Kali Linux) isolated on the same virtual network, used only for controlled simulated attacks.
   - Optional: pfSense or a simple firewall VM to generate network logs.
3. **Networking:** put everything on an isolated virtual network (host-only or a dedicated VirtualBox NAT network) so simulated attacks never touch the real internet or your host.
4. **Install Wazuh:**
   ```bash
   curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
   sudo bash wazuh-install.sh -a
   ```
   This installs the Wazuh indexer, manager, and dashboard together for a single-node deployment.
5. **Enroll agents** on each victim VM using the agent install command Wazuh gives you after setup (includes the manager IP and a registration key).

---

## Phase 3 — Log ingestion and normalization

1. Confirm agents are reporting: check **Agents** in the Wazuh dashboard.
2. Enable key log sources per OS:
   - Windows: Sysmon (install with a solid config like SwiftOnSecurity's) for process creation, network connections, registry changes — feed into Winlogbeat/Wazuh agent.
   - Linux: auditd rules for process exec, file access, and auth logs (`/var/log/auth.log`).
   - Network: firewall/DNS logs shipped via syslog to Wazuh or Logstash.
3. Verify normalization: Wazuh uses decoders/rulesets to parse raw logs into structured fields (source IP, user, event type). Check a few events in the dashboard to confirm fields are populating correctly — this matters a lot for the ML step, since your model will train on these structured fields.
4. Export a sample dataset (a few days of normal traffic) to CSV/JSON for offline model training — via the Wazuh API or by querying the underlying Elasticsearch/OpenSearch index.

---

## Phase 4 — AI/ML detection layer

This is the core "AI" part of the project. Build it as a separate Python service that periodically queries Wazuh's index, scores new events, and writes alerts back (either into Wazuh as custom rules or into your own alerts store).

### 4.1 Feature engineering

From raw logs, derive features such as:
- Login frequency per user per hour, failed-login ratio
- Number of distinct destination IPs/ports contacted per host per minute
- Process rarity (how often has this process name been seen before on this host)
- Bytes transferred, connection duration
- Time-of-day / day-of-week (encode cyclically)

### 4.2 Model options (start simple, layer up)

- **Unsupervised anomaly detection** — Isolation Forest or a small autoencoder trained only on "normal" baseline traffic; flags anything with high reconstruction error / anomaly score.
- **Supervised classification** — if you can get or simulate labeled malicious traffic (e.g., via Atomic Red Team runs labeled as "attack"), train a Random Forest or gradient-boosted classifier to distinguish benign vs malicious.
- **UEBA-style** — per-user/per-host baselines updated over a rolling window, flag deviations (e.g., a service account suddenly logging in interactively).

Example Isolation Forest sketch:
```python
from sklearn.ensemble import IsolationForest
import pandas as pd

df = pd.read_csv("baseline_features.csv")
model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
model.fit(df)

# score new events
new_events = pd.read_csv("live_features.csv")
scores = model.decision_function(new_events)
new_events["anomaly_score"] = scores
alerts = new_events[scores < model.threshold_] if hasattr(model, "threshold_") else new_events[scores < -0.1]
```

### 4.3 Wire it into the pipeline

- Run this as a scheduled job (cron / Airflow / simple `while True` loop with sleep) that pulls new logs every N minutes, scores them, and pushes flagged events into a Wazuh custom alert (via the Wazuh API or by writing to a monitored log file that Wazuh ingests) or directly into your SOAR tool's inbox.
- Track model performance over time — log predictions vs analyst-confirmed outcomes so you can compute precision/recall later.

---

## Phase 5 — Threat intelligence enrichment

1. Get free API keys: VirusTotal, AbuseIPDB, and optionally MISP (self-hosted or a public feed).
2. Write an enrichment step that, for every alert, looks up:
   - Source/destination IPs against AbuseIPDB
   - File hashes (if present) against VirusTotal
   - Domains against a DNS reputation feed
3. Add an "IOC match" boost to the anomaly score — an anomalous event that also matches a known-bad IP should be prioritized far above an anomaly with no external corroboration.
4. Cache lookups locally to respect free-tier API rate limits.

---

## Phase 6 — Incident response automation (SOAR)

1. Deploy Shuffle (or TheHive + Cortex) as a separate service.
2. Build 2–3 playbooks that trigger on high-confidence alerts:
   - **Playbook A — Suspicious login:** enrich IP → if malicious, disable the user account (via API) → create a ticket → notify analyst (email/Slack webhook).
   - **Playbook B — Malware indicator:** enrich hash → if malicious, isolate the host (e.g., trigger a Wazuh active-response script to firewall the host) → open a ticket.
   - **Playbook C — Brute force detected:** auto-block the source IP at the firewall for a cooldown period → log the action.
3. Wazuh has a built-in "active response" feature for simple automated actions (e.g., blocking an IP via `iptables`) that can be triggered directly from custom rules — useful if you want to skip standing up a separate SOAR tool for a smaller project.

---

## Phase 7 — Dashboards and alerting

1. Build a Kibana (or Grafana) dashboard showing:
   - Alert volume over time, by severity
   - Top source IPs / users generating alerts
   - Model-flagged anomalies vs rule-based detections
   - MTTD/MTTR trend
2. Set up notification channels: email or Slack/Discord webhook for high-severity alerts, so the "human in the loop" step of your demo is visible.

---

## Phase 8 — Test with simulated attacks

1. Use **Atomic Red Team** on the attacker VM to run scoped, safe attack techniques mapped to MITRE ATT&CK (e.g., T1110 brute force, T1059 command execution, T1071 C2 over HTTP).
2. Confirm each simulated technique produces logs, triggers the ML model, gets enriched, and (where scoped) fires a SOAR playbook.
3. Record before/after: how fast did the AI layer flag it vs a purely rule-based baseline (disable the ML scoring temporarily and compare).

---

## Phase 9 — Evaluate

Compute and report:
- **Precision / recall / F1** of the ML model on a labeled test set (mix of normal traffic + simulated attack traffic).
- **False positive rate** — critical for a SOC project since alert fatigue is the main real-world failure mode; discuss how you tuned thresholds to manage it.
- **MTTD/MTTR** with automation on vs off.
- Honest limitations: small dataset, simulated (not real-world) attack traffic, single-node scale.

---

## Phase 10 — Document and present

- Architecture diagram (like the one above) + data flow explanation.
- Short written report: problem statement, architecture, model choices and why, results, limitations, future work (e.g., adding UEBA, scaling to Kafka for log streaming, moving to a supervised model with more labeled data).
- Live or recorded demo: run one Atomic Red Team technique, show the alert appear, get enriched, and trigger an automated containment action, end to end.

---

## Suggested timeline (solo, part-time)

| Week | Focus |
|---|---|
| 1 | Scope, architecture, lab environment setup |
| 2 | Wazuh install, agent enrollment, log verification |
| 3–4 | Feature engineering + baseline ML model |
| 5 | Threat intel enrichment integration |
| 6 | SOAR playbooks + active response |
| 7 | Dashboards, alerting, attack simulation |
| 8 | Evaluation, report, demo polish |

This is a substantial project — if any single phase (e.g., the ML layer, or the SOAR automation) feels like it deserves more depth than fits here, I'm happy to go deeper on that phase specifically, including more complete code for the detection models or example playbook JSON.
