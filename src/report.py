"""Generate an HTML security report from findings.json."""
import json
import os
from datetime import datetime
from jinja2 import Template


# Copied from the Step 4 results (update if you retrain)
METRICS = [
    ("Random Forest (behaviour only)", 0.992, 0.984, 0.988, 1, 2),
    ("Isolation Forest (unsupervised)", 0.785, 0.907, 0.842, 32, 12),
]
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

TEMPLATE = Template("""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Report</title>
<style>
 body{font-family:Arial,sans-serif;max-width:1000px;margin:30px auto;color:#222}
 h1{border-bottom:3px solid #2a7;padding-bottom:6px}
 table{border-collapse:collapse;width:100%;margin:10px 0}
 th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:14px}
 th{background:#eef}
 .critical{background:#f8c9c9}.high{background:#fbdcb5}
 .medium{background:#fff3b0}.low{background:#d9f0d9}
 .card{border:1px solid #bbb;border-radius:6px;padding:12px;margin:14px 0}
 small{color:#666}
</style></head><body>
<h1>Security Analysis Report</h1>
<small>Generated {{ now }} | Pipeline: Random Forest detection ->
 correlation -> NIST CSF / ISO 27001 mapping</small>

<h2>1. Executive summary</h2>
<p>{{ findings|length }} incidents from {{ total_alerts }} flagged alerts.
 Risk levels: {% for k, v in risk_counts.items() %}{{ k }}: {{ v }}{% if not loop.last %}, {% endif %}{% endfor %}.</p>
<p><b>Affected assets:</b> {{ assets|join(", ") }}</p>

<h2>2. Incident overview</h2>
<table><tr><th>Incident</th><th>Type</th><th>Source IP</th><th>Asset</th>
<th>Alerts</th><th>Risk</th></tr>
{% for f in findings %}<tr class="{{ f.risk }}"><td>{{ f.incident }}</td>
<td>{{ f.title }}</td><td>{{ f.source_ip }}</td><td>{{ f.asset }}</td>
<td>{{ f.alerts }}</td><td>{{ f.risk }}</td></tr>{% endfor %}</table>

<h2>3. Detailed findings</h2>
{% for f in findings %}<div class="card"><h3>{{ f.incident }}: {{ f.title }}</h3>
<p><b>Risk:</b> {{ f.risk }} | <b>Max event severity:</b> {{ f.severity }} |
 <b>Time:</b> {{ f.start }} to {{ f.end }}</p>
<p><b>Source / asset:</b> {{ f.source_ip }} -> {{ f.asset }}</p>
<p><b>Evidence:</b> {{ f.evidence }}</p>
<p><b>NIST CSF:</b> {{ f.nist_csf }}<br><b>ISO 27001:</b> {{ f.iso_27001 }}</p>
<p><b>Remediation:</b> {{ f.remediation }}</p>
{% if f.threat_intel %}<p><b>Threat intel:</b> {{ f.threat_intel }}</p>{% endif %}
</div>{% endfor %}

<h2>4. Model performance (test period, Oct 24-25)</h2>
<table><tr><th>Model</th><th>Precision</th><th>Recall</th><th>F1</th>
<th>FP</th><th>FN</th></tr>
{% for m in metrics %}<tr><td>{{ m[0] }}</td><td>{{ m[1] }}</td>
<td>{{ m[2] }}</td><td>{{ m[3] }}</td><td>{{ m[4] }}</td><td>{{ m[5] }}</td></tr>{% endfor %}</table>

<h2>5. Limitations</h2>
<ul>
<li>Data is synthetic; real logs are noisier, so these metrics are optimistic.</li>
<li>Test period holds 3 incidents and no port scans.</li>
<li>Control mapping is illustrative and should be validated by a compliance specialist.</li>
<li>Incidents marked "low confidence" may be false positives and need analyst review.</li>
</ul>
</body></html>""")


def build_report(findings_path="data/processed/findings.json",
                 out_path="reports/security_report.html"):
    with open(findings_path) as f:
        findings = json.load(f)
    findings.sort(key=lambda x: RISK_ORDER.get(x["risk"], 9))
    risk_counts = {}
    for f in findings:
        risk_counts[f["risk"]] = risk_counts.get(f["risk"], 0) + 1
    html = TEMPLATE.render(
        findings=findings, metrics=METRICS, risk_counts=risk_counts,
        total_alerts=sum(f["alerts"] for f in findings),
        assets=sorted({f["asset"] for f in findings}),
        now=datetime.now().strftime("%Y-%m-%d %H:%M"))
    os.makedirs("reports", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path



if __name__ == "__main__":
    print("Report written to", build_report())


