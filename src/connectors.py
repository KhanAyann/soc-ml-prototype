"""Data connectors: log file source + AbuseIPDB threat intelligence."""
import os
import requests
from dotenv import load_dotenv
from preprocess import load_and_clean

load_dotenv()   # reads .env locally; .env is git-ignored


def fetch_logs_from_csv(path="data/raw/security_logs.csv"):
    """Connector 1: security logs from a file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Log file not found: {path}")
    return load_and_clean(path)


def ip_reputation(ip, timeout=5):
    """Connector 2: threat intel. Fails gracefully with no key or no network."""
    key = os.getenv("ABUSEIPDB_API_KEY")
    base = {"ip": ip, "source": "abuseipdb"}
    if not key:
        return {**base, "available": False, "reason": "no API key configured"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=timeout)
        r.raise_for_status()
        d = r.json()["data"]
        return {**base, "available": True,
                "abuse_score": d["abuseConfidenceScore"],
                "total_reports": d["totalReports"],
                "country": d.get("countryCode")}
    except (requests.RequestException, KeyError, ValueError) as e:
        return {**base, "available": False,
                "reason": f"lookup failed ({type(e).__name__})"}