# Step 2 : syntetic data generator



# step 2.1 : generate normal traffic
# Normal traffic generator

"""Synthetic security log generator. Part 1: normal traffic."""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

SEED = 42                      # fixed seed -> same data every run
START = datetime(2026, 10, 19)
DAYS = 7
N_NORMAL = 9000

ASSETS = ["web-server-01", "db-server-01", "file-server-01",
          "mail-server-01", "app-server-01", "vpn-gateway"]
USERS = [f"user{i:02d}" for i in range(1, 26)]

# event_type: (weight, possible ports, median bytes_out, severity)
NORMAL_EVENTS = {
    "login_success":   (0.55, [22, 443, 3389], 2_000,   "low"),
    "login_failed":    (0.05, [22, 443, 3389], 1_500,   "low"),
    "file_access":     (0.20, [445],           50_000,  "low"),
    "data_transfer":   (0.15, [443],           500_000, "low"),
    "config_change":   (0.03, [22],            3_000,   "medium"),
    "service_restart": (0.02, [22],            1_000,   "medium"),
}

# Busy 9-17, lighter evenings/early morning, almost nothing at night
_w = np.full(24, 0.3)
_w[7:9] = 3
_w[9:18] = 10
_w[18:21] = 3
HOUR_WEIGHTS = _w / _w.sum()


def _timestamps(n, rng):
    days = rng.integers(0, DAYS, n)
    hours = rng.choice(24, size=n, p=HOUR_WEIGHTS)
    secs = rng.integers(0, 3600, n)
    return [START + timedelta(days=int(d), hours=int(h), seconds=int(s))
            for d, h, s in zip(days, hours, secs)]


def generate_normal(n=N_NORMAL, seed=SEED):
    rng = np.random.default_rng(seed)
    user_ip = {u: f"10.0.{rng.integers(1, 5)}.{rng.integers(10, 250)}"
               for u in USERS}                       # each user has a home IP

    types = list(NORMAL_EVENTS)
    probs = [NORMAL_EVENTS[t][0] for t in types]
    chosen = rng.choice(types, size=n, p=probs)
    stamps = _timestamps(n, rng)

    rows = []
    for ev, ts in zip(chosen, stamps):
        _, ports, median, sev = NORMAL_EVENTS[ev]
        user = USERS[rng.integers(len(USERS))]
        row = dict(
            timestamp=ts, source_ip=user_ip[user],
            dest_asset=ASSETS[rng.integers(len(ASSETS))], user=user,
            event_type=ev, dest_port=int(rng.choice(ports)),
            bytes_out=int(rng.lognormal(np.log(median), 0.6)),
            severity=sev, is_suspicious=0,
            scenario_id=None, attack_type="normal",
        )
        rows.append(row)

        # A typo: failed login, maybe a 2nd failure, then a success
        if ev == "login_failed":
            t = ts
            for _ in range(rng.integers(0, 2)):          # 0 or 1 extra fail
                t += timedelta(seconds=int(rng.integers(3, 15)))
                rows.append({**row, "timestamp": t})
            t += timedelta(seconds=int(rng.integers(5, 20)))
            rows.append({**row, "timestamp": t, "event_type": "login_success"})

    return pd.DataFrame(rows)


# Step 2b: Attack generators

def _atk_row(ts, ip, asset, user, ev, port, bytes_out, sev, sid, atype):
    return dict(timestamp=ts, source_ip=ip, dest_asset=asset, user=user,
                event_type=ev, dest_port=port, bytes_out=bytes_out,
                severity=sev, is_suspicious=1,
                scenario_id=sid, attack_type=atype)


def gen_brute_force(rng, start, ip, asset, sid, n=None, success=True):
    """Many failed logins from one external IP, cycling usernames."""
    n = n or int(rng.integers(40, 100))
    targets = ["admin", "root", "user01", "user02", "svc_backup", "administrator"]
    rows, t = [], start
    for _ in range(n):
        t += timedelta(seconds=float(rng.uniform(0.5, 4)))   # fast and sustained
        rows.append(_atk_row(t, ip, asset, str(rng.choice(targets)),
                             "login_failed", 22, int(rng.integers(300, 900)),
                             "medium", sid, "brute_force"))
    if success:                                              # eventually gets in
        t += timedelta(seconds=int(rng.integers(2, 10)))
        rows.append(_atk_row(t, ip, asset, "admin", "login_success", 22,
                             1_200, "high", sid, "brute_force"))
    return rows, t


def gen_port_scan(rng, start, ip, asset, sid):
    """One IP probes many different ports on one asset in seconds."""
    ports = rng.choice(np.arange(1, 1024), size=int(rng.integers(20, 50)),
                       replace=False)
    rows, t = [], start
    for p in ports:
        t += timedelta(seconds=float(rng.uniform(0.05, 0.6)))
        rows.append(_atk_row(t, ip, asset, "unknown", "port_probe", int(p),
                             int(rng.integers(40, 120)), "medium",
                             sid, "port_scan"))
    return rows, t




# Step 2c: Multi-stage chain attack scenarios

def gen_exfiltration(rng, start, ip, asset, sid, user="admin"):
    """Very large outbound transfers to an external IP, at night."""
    rows, t = [], start
    for _ in range(int(rng.integers(3, 8))):
        t += timedelta(minutes=float(rng.uniform(1, 10)))
        rows.append(_atk_row(t, ip, asset, user, "data_transfer", 443,
                             int(rng.integers(20_000_000, 90_000_000)),
                             "high", sid, "exfiltration"))
    return rows, t


def gen_multi_stage(rng, start, ip, asset, sid):
    """Brute force -> login -> privilege escalation -> exfiltration."""
    rows, t = gen_brute_force(rng, start, ip, asset, sid, success=True)
    t += timedelta(minutes=float(rng.uniform(2, 10)))
    rows.append(_atk_row(t, ip, asset, "admin", "privilege_escalation", 22,
                         2_000, "high", sid, "multi_stage"))
    ex_rows, t = gen_exfiltration(rng, t + timedelta(minutes=5), ip, asset, sid)
    for r in ex_rows:
        r["attack_type"] = "multi_stage"
    rows += ex_rows
    for r in rows:
        r["attack_type"] = "multi_stage"
    return rows, t


def generate_dataset(seed=SEED):
    rng = np.random.default_rng(seed)
    df_normal = generate_normal(seed=seed)

    def at(day, hour, minute=0):
        return START + timedelta(days=day, hours=hour, minutes=minute)

    attack_rows = []
    plan = [  # (generator, start time, attacker ip, asset, scenario id)
        (gen_brute_force,  at(1, 14, 10), "185.220.101.4",  "vpn-gateway",    "INC-001"),
        (gen_port_scan,    at(2, 9, 30),  "45.155.205.12",  "web-server-01",  "INC-002"),
        (gen_exfiltration, at(3, 3, 5),   "103.75.201.9",   "db-server-01",   "INC-003"),
        (gen_multi_stage,  at(4, 2, 20),  "91.240.118.77",  "app-server-01",  "INC-004"),
        (gen_brute_force,  at(5, 22, 40), "178.62.55.31",   "mail-server-01", "INC-005"),        (gen_port_scan,    at(0, 16, 45), "198.51.100.23", "db-server-01",   "INC-006"),
        (gen_exfiltration, at(5, 1, 30),  "203.0.113.50",  "file-server-01", "INC-007"),
        (gen_multi_stage,  at(6, 3, 10),  "194.26.29.15",  "web-server-01",  "INC-008"),
        (gen_brute_force,  at(0, 23, 15), "62.210.37.9",   "app-server-01",  "INC-009"),
        (gen_exfiltration, at(2, 2, 40),  "185.141.27.6",  "mail-server-01", "INC-010"),
    ]
    for gen, start, ip, asset, sid in plan:
        rows, _ = gen(rng, start, ip, asset, sid)
        attack_rows += rows

    df = pd.concat([df_normal, pd.DataFrame(attack_rows)], ignore_index=True)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.insert(0, "event_id", range(1, len(df) + 1))
    return df








if __name__ == "__main__":
    import os
    df = generate_dataset()
    os.makedirs("data/raw", exist_ok=True)
    df.to_csv("data/raw/security_logs.csv", index=False)
    print("Shape:", df.shape)
    print("Suspicious %:", round(df["is_suspicious"].mean() * 100, 2))
    print(df["attack_type"].value_counts())
    print(df.groupby("scenario_id").size())



