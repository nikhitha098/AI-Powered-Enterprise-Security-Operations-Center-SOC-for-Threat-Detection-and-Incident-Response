"""
Synthetic security event log generator.

Produces a CSV of authentication + network connection events for a small
simulated enterprise (N hosts, M users) over several days, with a mix of
normal background activity and injected attack patterns:

  - brute_force   : many failed logins from one source against one user
  - port_scan     : one host contacting many distinct ports on a target in a short window
  - c2_beacon     : a host making regular, low-volume outbound connections to one IP (beaconing)
  - data_exfil    : a host sending an unusually large volume of bytes outbound

Each row is a single event with a ground-truth `is_attack` / `attack_type`
label so the ML pipeline can be evaluated with real precision/recall numbers.
This is a stand-in for what a real deployment would pull from Wazuh /
Winlogbeat / firewall syslog — the feature engineering and modeling code
downstream doesn't care whether the rows came from here or from a live SIEM.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

OUT_PATH = Path(__file__).parent / "sample_logs.csv"

HOSTS = [f"host-{i:02d}" for i in range(1, 21)]
USERS = [f"user{i:02d}" for i in range(1, 31)] + ["svc_backup", "svc_web", "admin"]
INTERNAL_SUBNET = "10.0.0."
EXTERNAL_IPS = [f"185.220.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(50)]
COMMON_PORTS = [80, 443, 22, 3389, 445, 53]

START = datetime(2026, 6, 1, 0, 0, 0)
DAYS = 5


def rand_time(day_offset):
    base = START + timedelta(days=day_offset)
    return base + timedelta(seconds=random.randint(0, 86399))


def normal_login_events(n):
    rows = []
    for _ in range(n):
        t = rand_time(random.randint(0, DAYS - 1))
        # normal logins cluster during working hours on weekdays
        hour = random.choices(range(24), weights=[1]*6 + [4]*10 + [2]*8)[0]
        t = t.replace(hour=hour)
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "login",
            "host": random.choice(HOSTS),
            "user": random.choice(USERS),
            "src_ip": INTERNAL_SUBNET + str(random.randint(2, 254)),
            "dst_ip": "",
            "dst_port": "",
            "status": "success" if random.random() > 0.05 else "failed",
            "bytes_out": 0,
            "is_attack": 0,
            "attack_type": "",
        })
    return rows


def normal_network_events(n):
    rows = []
    for _ in range(n):
        t = rand_time(random.randint(0, DAYS - 1))
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "network",
            "host": random.choice(HOSTS),
            "user": "",
            "src_ip": INTERNAL_SUBNET + str(random.randint(2, 254)),
            "dst_ip": random.choice(EXTERNAL_IPS + [INTERNAL_SUBNET + str(random.randint(2, 254))]),
            "dst_port": random.choice(COMMON_PORTS),
            "status": "success",
            "bytes_out": random.randint(500, 50000),
            "is_attack": 0,
            "attack_type": "",
        })
    return rows


def brute_force_events():
    rows = []
    victim_user = random.choice(USERS)
    attacker_ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    start = rand_time(random.randint(0, DAYS - 1))
    for i in range(40):
        t = start + timedelta(seconds=i * random.randint(2, 8))
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "login",
            "host": host,
            "user": victim_user,
            "src_ip": attacker_ip,
            "dst_ip": "",
            "dst_port": "",
            "status": "failed" if i < 38 else "success",
            "bytes_out": 0,
            "is_attack": 1,
            "attack_type": "brute_force",
        })
    return rows


def port_scan_events():
    rows = []
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_host = random.choice(HOSTS)
    start = rand_time(random.randint(0, DAYS - 1))
    ports = random.sample(range(1, 65535), 60)
    for i, p in enumerate(ports):
        t = start + timedelta(seconds=i * random.uniform(0.1, 1.0))
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "network",
            "host": target_host,
            "user": "",
            "src_ip": attacker_ip,
            "dst_ip": INTERNAL_SUBNET + str(random.randint(2, 254)),
            "dst_port": p,
            "status": "success",
            "bytes_out": random.randint(0, 200),
            "is_attack": 1,
            "attack_type": "port_scan",
        })
    return rows


def c2_beacon_events():
    rows = []
    host = random.choice(HOSTS)
    c2_ip = random.choice(EXTERNAL_IPS)
    start = rand_time(random.randint(0, DAYS - 2))
    for i in range(30):
        t = start + timedelta(minutes=i * 5 + random.uniform(-0.2, 0.2))
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "network",
            "host": host,
            "user": "",
            "src_ip": INTERNAL_SUBNET + str(random.randint(2, 254)),
            "dst_ip": c2_ip,
            "dst_port": 443,
            "status": "success",
            "bytes_out": random.randint(200, 600),
            "is_attack": 1,
            "attack_type": "c2_beacon",
        })
    return rows


def data_exfil_events():
    rows = []
    host = random.choice(HOSTS)
    dst_ip = random.choice(EXTERNAL_IPS)
    t = rand_time(random.randint(0, DAYS - 1))
    for i in range(5):
        rows.append({
            "timestamp": (t + timedelta(seconds=i * 3)).isoformat(),
            "event_type": "network",
            "host": host,
            "user": "",
            "src_ip": INTERNAL_SUBNET + str(random.randint(2, 254)),
            "dst_ip": dst_ip,
            "dst_port": 443,
            "status": "success",
            "bytes_out": random.randint(5_000_000, 20_000_000),
            "is_attack": 1,
            "attack_type": "data_exfil",
        })
    return rows


def main():
    rows = []
    rows += normal_login_events(3000)
    rows += normal_network_events(6000)

    # inject a handful of each attack pattern spread across the period
    for _ in range(4):
        rows += brute_force_events()
    for _ in range(3):
        rows += port_scan_events()
    for _ in range(3):
        rows += c2_beacon_events()
    for _ in range(2):
        rows += data_exfil_events()

    rows.sort(key=lambda r: r["timestamp"])

    fieldnames = ["timestamp", "event_type", "host", "user", "src_ip", "dst_ip",
                  "dst_port", "status", "bytes_out", "is_attack", "attack_type"]
    with open(OUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    n_attack = sum(r["is_attack"] for r in rows)
    print(f"Wrote {len(rows)} events ({n_attack} labeled attack events) to {OUT_PATH}")


if __name__ == "__main__":
    main()
