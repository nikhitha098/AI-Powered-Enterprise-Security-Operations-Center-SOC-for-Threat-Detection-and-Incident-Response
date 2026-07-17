# AI-Powered Enterprise SOC — Threat Detection and Incident Response

A working, runnable demonstration of an AI-driven Security Operations Center pipeline:
synthetic enterprise log generation → windowed feature engineering → dual ML detection
(unsupervised Isolation Forest + supervised Random Forest) → threat intel enrichment →
automated SOAR playbooks → analyst dashboard.

Everything runs locally with no external services required (threat intel falls back to an
offline mock IOC list, response actions are simulated but logged with the exact API call a
real integration would make). See `docs/architecture.md` for how each stage maps to a real
deployment (Wazuh, ELK, live threat intel APIs, a real SOAR tool).

## Quick start

```bash
git clone <your-repo-url>
cd ai-soc-project
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run the full pipeline: generate data -> features -> train models -> detect -> enrich -> respond
python3 main.py

# Launch the analyst dashboard
python3 src/dashboard/app.py
# open http://localhost:5000
```

Run tests:
```bash
pytest -v
```

## What you'll see

- `python3 main.py` prints precision/recall for both models on a held-out test set, then
  the number of alerts flagged, how many matched known-bad indicators, and how many SOAR
  playbooks fired.
- The dashboard shows severity breakdown, top offending IPs/hosts, a ranked alert table
  (with ground-truth labels so you can visually sanity-check the model), a feed of
  automated response actions, and the model evaluation metrics.

## Project structure

```
ai-soc-project/
├── main.py                        # orchestrates the full pipeline end to end
├── data/
│   └── generate_sample_logs.py    # synthetic log generator (brute force, port scan, C2, exfil)
├── src/
│   ├── features/
│   │   └── feature_engineering.py # raw events -> windowed numeric features
│   ├── models/
│   │   ├── train_model.py         # trains Isolation Forest + Random Forest, saves metrics
│   │   └── detect.py              # scores events, produces alerts.json
│   ├── enrichment/
│   │   ├── threat_intel.py        # AbuseIPDB/VirusTotal lookups (or offline mock)
│   │   └── mock_iocs.json         # offline IOC list used when no API keys are set
│   ├── soar/
│   │   └── playbooks.py           # rule-based automated response actions
│   └── dashboard/
│       ├── app.py                 # Flask app serving the dashboard + JSON APIs
│       └── templates/index.html   # dashboard UI (Chart.js)
├── tests/
│   └── test_pipeline.py           # pytest suite for feature engineering + playbook logic
├── docs/
│   └── architecture.md            # design decisions, real-deployment mapping, limitations
├── .github/workflows/ci.yml       # GitHub Actions: installs deps, runs tests + full pipeline
├── requirements.txt
├── LICENSE
└── README.md
```

## Using real threat intelligence APIs

By default the enrichment step uses an offline mock IOC list so the project runs with zero
setup. To use live lookups instead, get free API keys and export them before running:

```bash
export ABUSEIPDB_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
python3 src/enrichment/threat_intel.py
```

- AbuseIPDB free tier: https://www.abuseipdb.com/register
- VirusTotal free tier: https://www.virustotal.com/gui/join-us

## Example results (synthetic test set)

| Model | Precision | Recall | F1 |
|---|---|---|---|
| Isolation Forest (unsupervised) | ~0.15 | ~0.29 | ~0.20 |
| Random Forest (supervised) | ~0.78 | ~0.92 | ~0.84 |

This gap is expected and worth explaining in a writeup or presentation: the unsupervised
model has never seen a label and is purely flagging statistical outliers, so it has much
lower precision but still catches nearly a third of attacks with zero labeled training
data. The supervised model performs far better once given confirmed examples — which is
exactly the tradeoff a real SOC faces as it matures from "no labeled incidents yet" to
"a growing backlog of triaged cases."

## Extending this project

- Swap the synthetic generator for real Wazuh/Winlogbeat output (see `docs/architecture.md`
  for the exact interface each stage expects).
- Add an autoencoder-based anomaly detector alongside Isolation Forest.
- Add per-user/per-host rolling baselines for a UEBA-style detector.
- Replace the simulated SOAR actions in `src/soar/playbooks.py` with real API calls to your
  EDR, firewall, IAM, and ticketing system.
- Swap the Flask/Chart.js dashboard for Kibana or Grafana reading directly from a live SIEM
  index.

## License

MIT — see `LICENSE`.
