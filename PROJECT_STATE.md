# PROJECT STATE
## Goal
Mini SOC prototype for the Kapstone AI/ML Intern assessment: ML detection,
alert correlation, compliance mapping, API, report.

## Decisions
- Local VS Code project (not Colab); synthetic dataset with injected attacks
- Models: RandomForest (supervised) vs IsolationForest (unsupervised)
- Stack: pandas, scikit-learn, FastAPI, Pydantic, Jinja2

## Done
- [x] Step 1: Setup

## Next
Step 2: synthetic dataset generator:

     Dataset design -> generator (src/data_generator.py)

## Dataset design
Columns: event_id, timestamp, source_ip, dest_asset, user, event_type,
dest_port, bytes_out, severity, is_suspicious (label), scenario_id and
attack_type (ground truth, never model inputs).
Attacks: brute_force, port_scan, exfiltration, multi_stage chain.
~8-10k normal events, 4-6 incidents (~3-5% suspicious).
Planned features: hour, is_external_ip, bytes_out, failed logins per IP
in last 5 min. Metrics: precision/recall/F1, not accuracy.

## Metrics / Notes
(none yet)