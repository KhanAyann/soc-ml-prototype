"""Preprocessing: cleaning + basic features. Part 1."""
import numpy as np
import pandas as pd

# Step 3a: Cleaning and basic features

REQUIRED_COLS = ["event_id", "timestamp", "source_ip", "dest_asset", "user",
                 "event_type", "dest_port", "bytes_out", "severity"]
SEVERITY_MAP = {"low": 0, "medium": 1, "high": 2}


def load_and_clean(path):
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "source_ip", "event_type"])
    df = df.drop_duplicates(subset=["event_id"])
    df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0)
    df["dest_port"] = pd.to_numeric(df["dest_port"], errors="coerce").fillna(0).astype(int)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def add_basic_features(df):
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    df["is_night"] = df["hour"].between(0, 5).astype(int)
    df["is_external_ip"] = (~df["source_ip"].str.startswith("10.")).astype(int)
    df["log_bytes_out"] = np.log1p(df["bytes_out"])
    df["severity_num"] = df["severity"].map(SEVERITY_MAP).fillna(0).astype(int)
    return df


# Step 3b: Backward-looking window features

def _window_count(group, window, mask=None, distinct_col=None):
    """For each row: count rows from the same IP in the previous `window`,
    including the current row, never looking forward."""
    g = group.set_index("timestamp")
    if distinct_col:
        out = (g[distinct_col].rolling(window)
               .apply(lambda s: len(set(s)), raw=False))
    else:
        s = g["_flag"] if mask is not None else g["_one"]
        out = s.rolling(window).sum()
    return out.values


def add_window_features(df):
    df = df.copy().sort_values("timestamp").reset_index(drop=True)
    df["_one"] = 1
    df["_flag"] = (df["event_type"] == "login_failed").astype(int)
    df["fails_5min"] = 0.0
    df["events_1min"] = 0.0
    df["distinct_ports_1min"] = 0.0

    for ip, idx in df.groupby("source_ip").groups.items():
        g = df.loc[idx]
        df.loc[idx, "fails_5min"] = _window_count(g, "5min", mask=True)
        df.loc[idx, "events_1min"] = _window_count(g, "1min")
        df.loc[idx, "distinct_ports_1min"] = _window_count(
            g, "1min", distinct_col="dest_port")

    return df.drop(columns=["_one", "_flag"])




if __name__ == "__main__":
    df = load_and_clean("data/raw/security_logs.csv")
    df = add_basic_features(df)
    df = add_window_features(df)
    cols = ["fails_5min", "events_1min", "distinct_ports_1min"]
    print(df.shape)
    print(df.groupby("is_suspicious")[cols].agg(["mean", "max"]).round(2))