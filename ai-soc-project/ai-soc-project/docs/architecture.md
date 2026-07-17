# Architecture

## Pipeline overview

```
Log sources → Feature engineering → ML detection → Threat intel enrichment → SOAR playbooks → Dashboard
```

This repo implements a runnable, self-contained version of that pipeline using synthetic
data so the whole thing works offline with no external services. Each stage is a
separate, swappable module — the interface between stages is plain CSV/JSON, so any
stage can be replaced with a real system without touching the others.

| Stage | This repo | Real deployment equivalent |
|---|---|---|
| Log source | `data/generate_sample_logs.py` (synthetic events) | Wazuh agents, Winlogbeat, Sysmon, firewall syslog |
| Feature engineering | `src/features/feature_engineering.py` | Same logic, pointed at a live SIEM index (Elasticsearch/OpenSearch query instead of CSV) |
| Detection | `src/models/train_model.py`, `detect.py` | Same models, retrained periodically on real traffic; add more model types (autoencoder, per-user baselines) as data grows |
| Threat intel | `src/enrichment/threat_intel.py` | Same code — set `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` env vars to switch from the offline mock IOC list to live lookups |
| Response | `src/soar/playbooks.py` | Same decision logic — replace each `action_*` function body with a real API call (EDR isolate, firewall block, IAM disable, ticketing system) |
| Dashboard | `src/dashboard/app.py` (Flask, reads JSON files) | Kibana/Grafana panels reading from the SIEM index directly |

## Why two models

- **Isolation Forest** is unsupervised — it never sees labels, only learns what "normal"
  traffic looks like from the training set. This is what a real deployment can use from
  day one, before you've accumulated any confirmed incidents to train on. Recall on rare,
  novel attack patterns is its strength; precision is its weakness (see `metrics.json` —
  it flags a lot of false positives because "unusual" isn't the same as "malicious").
- **Random Forest** is supervised — trained on the `attack_present` ground-truth label.
  Once you have a backlog of analyst-confirmed incidents (even a few hundred), a
  supervised model gets dramatically better precision/recall on patterns similar to what
  it's seen. The tradeoff is it won't generalize well to attack types it's never seen.

Combining both (`detect.py` flags a window if *either* model considers it suspicious,
and assigns higher severity when *both* agree) is a standard pattern in real detection
engineering: unsupervised models catch novel things, supervised models catch known things
with better precision, and agreement between them is a strong signal.

## Windowed features, not raw events

Almost none of the attack patterns here are visible from a single event — a single failed
login is normal, forty in sixty seconds from one IP is a brute force. `feature_engineering.py`
buckets events into 1-minute windows per `(host, src_ip)` pair and computes aggregate features
(failed login count, distinct ports contacted, bytes transferred, etc.) per window. This is
the same reason real SIEM/UEBA tools operate on rolling windows rather than raw events.

## Severity and alert scoring logic

1. A window gets flagged if the Isolation Forest anomaly score crosses its threshold OR the
   Random Forest attack probability crosses 0.5.
2. Base severity: `high` if both models agree, `medium` if only one does.
3. Threat intel enrichment can escalate severity to `high` regardless of the model
   disagreement, if the source IP matches a known-bad indicator — external corroboration is
   treated as strong evidence on its own.
4. SOAR playbook selection then runs off the final alert (features + severity + threat
   intel), not the raw model output — this keeps the response logic auditable and testable
   independent of model internals (see `tests/test_pipeline.py`).

## Known limitations (worth stating explicitly in a writeup)

- Training and test data both come from the same synthetic generator, so the reported
  precision/recall numbers describe how well the model fits synthetic patterns, not
  real-world attack traffic. Treat them as a demonstration of the *methodology*, not a
  claim about production performance.
- Single-node scale; no attempt at high availability or horizontal scaling of the
  detection layer.
- The mock IOC list is hand-seeded with a handful of the generator's own simulated
  attacker IPs, purely so the enrichment step has something to match against offline —
  it is not a real threat feed.
