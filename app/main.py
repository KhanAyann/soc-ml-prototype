"""FastAPI backend: validate logs -> detect -> correlate -> map compliance."""
import sys
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT / "src"))

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from connectors import fetch_logs_from_csv, ip_reputation
from train import build_features
from correlate import correlate, summarize
from compliance import map_findings

app = FastAPI(title="Mini SOC API", version="1.0")

try:
    BUNDLE = joblib.load(ROOT / "models" / "rf_model.joblib")
except FileNotFoundError:
    BUNDLE = None


class LogEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    dest_asset: str = Field(min_length=1, max_length=64)
    user: str = Field(default="unknown", max_length=64)
    event_type: Literal["login_success", "login_failed", "file_access",
                        "data_transfer", "config_change", "service_restart",
                        "port_probe", "privilege_escalation"]
    dest_port: int = Field(ge=0, le=65535)
    bytes_out: int = Field(ge=0)
    severity: Literal["low", "medium", "high"]

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, v):
        return str(IPv4Address(v))      # raises -> HTTP 422


class AnalyzeRequest(BaseModel):
    events: list[LogEvent] = Field(min_length=1, max_length=5000)


def analyze(df, enrich=False):
    if BUNDLE is None:
        raise HTTPException(503, "Model not found. Run: python src/train.py")
    try:
        df = build_features(df)
        df["pred"] = BUNDLE["model"].predict(df[BUNDLE["features"]])
        alerts = correlate(df)
        if alerts.empty:
            return {"events_analyzed": len(df), "alerts_flagged": 0,
                    "incidents": []}
        findings = map_findings(alerts, summarize(alerts))
        if enrich:
            for f in findings:
                if not f["source_ip"].startswith("10."):
                    f["threat_intel"] = ip_reputation(f["source_ip"])
        return {"events_analyzed": len(df), "alerts_flagged": len(alerts),
                "incidents": findings}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, "Analysis failed. Check the server logs.")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": BUNDLE is not None}


@app.post("/analyze")
def analyze_events(req: AnalyzeRequest, enrich: bool = False):
    df = pd.DataFrame([e.model_dump() for e in req.events])
    df["event_id"] = range(1, len(df) + 1)
    return analyze(df, enrich)


@app.get("/analyze/sample")
def analyze_sample(enrich: bool = False):
    try:
        df = fetch_logs_from_csv(str(ROOT / "data/raw/security_logs.csv"))
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    return analyze(df, enrich)