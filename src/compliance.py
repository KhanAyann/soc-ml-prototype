"""Map correlated incidents to NIST CSF / ISO 27001 controls."""
import json
import pandas as pd

with open("config/compliance_map.json") as f:
    CONTROLS = json.load(f)


def classify(g):
    """Rule-based finding type from the events inside one incident."""
    types = g["event_type"].value_counts()
    if "privilege_escalation" in types:
        return "multi_stage_intrusion"
    if "port_probe" in types:
        return "port_scan"
    if types.get("login_failed", 0) >= 10:
        return "brute_force"
    if "data_transfer" in types and g["bytes_out"].max() > 10_000_000:
        return "data_exfiltration"
    return "low_confidence_anomaly"


def map_findings(alerts, summary):
    findings = []
    for _, inc in summary.iterrows():
        g = alerts[alerts["incident_key"] == inc["incident"]]
        ftype = classify(g)
        c = CONTROLS[ftype]
        findings.append(dict(
            incident=inc["incident"], finding_type=ftype, title=c["title"],
            source_ip=inc["source_ip"], asset=inc["asset"],
            alerts=int(inc["alerts"]), start=str(inc["start"]),
            end=str(inc["end"]), severity=inc["max_severity"],
            risk=c["risk"], nist_csf=c["nist_csf"], iso_27001=c["iso_27001"],
            evidence=inc["reason"], remediation=c["remediation"]))
    return findings


if __name__ == "__main__":
    alerts = pd.read_csv("data/processed/alerts.csv", parse_dates=["timestamp"])
    summary = pd.read_csv("data/processed/incidents.csv",
                          parse_dates=["start", "end"])
    findings = map_findings(alerts, summary)
    with open("data/processed/findings.json", "w") as f:
        json.dump(findings, f, indent=2)
    df = pd.DataFrame(findings)
    print(df[["incident", "source_ip", "finding_type", "risk"]])
    print("\n", df["finding_type"].value_counts().to_dict())