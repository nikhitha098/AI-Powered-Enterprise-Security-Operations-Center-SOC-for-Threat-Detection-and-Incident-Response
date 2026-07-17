"""
Run the entire AI-SOC pipeline end to end:

  1. Generate synthetic log data (skip if data/sample_logs.csv already exists)
  2. Build ML features from the raw events
  3. Train the Isolation Forest + Random Forest detection models
  4. Score events and produce alerts
  5. Enrich alerts with threat intelligence
  6. Run SOAR playbooks against the enriched alerts

After this completes, run the dashboard separately with:
    python3 src/dashboard/app.py
and open http://localhost:5000
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd, label):
    print(f"\n{'='*60}\n{label}\n{'='*60}")
    result = subprocess.run([sys.executable] + cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"Step failed: {label}")
        sys.exit(result.returncode)


def main():
    logs_path = ROOT / "data" / "sample_logs.csv"
    if not logs_path.exists():
        run(["data/generate_sample_logs.py"], "1/6 Generating synthetic log data")
    else:
        print("1/6 Skipping log generation (data/sample_logs.csv already exists)")

    run(["src/features/feature_engineering.py"], "2/6 Building ML features")
    run(["src/models/train_model.py"], "3/6 Training detection models")
    run(["src/models/detect.py"], "4/6 Scoring events and producing alerts")
    run(["src/enrichment/threat_intel.py"], "5/6 Enriching alerts with threat intel")
    run(["src/soar/playbooks.py"], "6/6 Running SOAR playbooks")

    print("\nPipeline complete. Start the dashboard with:")
    print("    python3 src/dashboard/app.py")
    print("Then open http://localhost:5000")


if __name__ == "__main__":
    main()
