"""Alert correlation: group flagged events into incidents."""
import pandas as pd

GAP_MINUTES = 30
SEV_NAME = {0: "low", 1: "medium", 2: "high"}


def correlate(df, flag_col="pred", gap_minutes=GAP_MINUTES):
    """Group flagged rows by source_ip + asset, splitting on time gaps."""
    alerts = df[df[flag_col] == 1].sort_values("timestamp").copy()
    alerts["incident_key"] = None
    n = 0
    for (ip, asset), g in alerts.groupby(["source_ip", "dest_asset"]):
        gaps = g["timestamp"].diff() > pd.Timedelta(minutes=gap_minutes)
        local = gaps.cumsum()            # increases by 1 at every big gap
        for k in local.unique():
            n += 1
            alerts.loc[g.index[local == k], "incident_key"] = f"CORR-{n:03d}"
    return alerts


def summarize(alerts):
    """One row per correlated incident, with a plain-English reason."""
    out = []
    for key, g in alerts.groupby("incident_key"):
        types = g["event_type"].value_counts().to_dict()
        mins = (g["timestamp"].max() - g["timestamp"].min()).total_seconds() / 60
        reason = (f"{len(g)} alerts from {g.source_ip.iloc[0]} on "
                  f"{g.dest_asset.iloc[0]} over {mins:.1f} min; "
                  f"events: {types}")
        out.append(dict(incident=key, source_ip=g.source_ip.iloc[0],
                        asset=g.dest_asset.iloc[0], start=g.timestamp.min(),
                        end=g.timestamp.max(), alerts=len(g),
                        max_severity=SEV_NAME[int(g.severity_num.max())],
                        reason=reason))
    return pd.DataFrame(out)







if __name__ == "__main__":
    import joblib
    from train import build_features
    from preprocess import load_and_clean

    bundle = joblib.load("models/rf_model.joblib")
    df = build_features(load_and_clean("data/raw/security_logs.csv"))
    df["pred"] = bundle["model"].predict(df[bundle["features"]])
    alerts = correlate(df)
    summary = summarize(alerts)
    pd.set_option("display.width", 200, "display.max_colwidth", 90)
    print(summary[["incident", "source_ip", "asset", "alerts", "max_severity"]])
    print("\nFlagged rows:", len(alerts), "| incidents found:", len(summary))


        # Grade against ground truth
    truth = alerts[alerts.scenario_id.notna()]
    per_inc = truth.groupby("scenario_id")["incident_key"].nunique()
    per_key = truth.groupby("incident_key")["scenario_id"].nunique()
    print("\nUnder-merge check (should be all 1):\n", per_inc.to_dict())
    print("Over-merge check (should be all 1):\n", per_key.to_dict())
    summary.to_csv("data/processed/incidents.csv", index=False)
    alerts.to_csv("data/processed/alerts.csv", index=False)