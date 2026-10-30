# PROJECT STATE
## Goal
Mini SOC prototype for the Kapstone AI/ML Intern assessment: ML detection,
alert correlation, compliance mapping, API, report.

## Decisions
- Local VS Code project (not Colab); synthetic dataset with injected attacks
- Models: RandomForest (supervised) vs IsolationForest (unsupervised)
- Stack: pandas, scikit-learn, FastAPI, Pydantic, Jinja2

## Done
- [x] Step 1: Setup (venv, structure, requirements, .gitignore)
- [x] Step 2: Dataset generator (src/data_generator.py)

Step 2: synthetic dataset generator:

     Dataset design -> generator (src/data_generator.py)

- [x] Step 3: preprocess.py done (basic + backward window features).
  fails_5min: normal max 4 vs attack max 78. Early rows of an attack look
  like typos -> expect imperfect recall.

## Dataset facts
- File: data/raw/security_logs.csv, 10,112 rows, 12 columns, seed=42
- Suspicious: 393 rows (3.89%), 10 incidents INC-001..INC-010
- attack_type counts: normal 9719, brute_force 184, multi_stage 125,
  port_scan 72, exfiltration 12
- Columns: event_id, timestamp, source_ip, dest_asset, user, event_type,
  dest_port, bytes_out, severity, is_suspicious (LABEL), scenario_id and
  attack_type (ground truth, NEVER model inputs)
- Known limitations: port_probe and privilege_escalation never occur in
  normal traffic (too easy); exfiltration only 12 rows (report per-type
  recall); synthetic data is cleaner than real logs.
- Correlation tests: INC-001 vs INC-005 (similar attacks, must stay
  separate), INC-004/008 (multi-stage, must merge)

Step 3: preprocess.py (cleaning + features) -> train.py

    - Step 3a result: is_external_ip separates classes perfectly (0% vs 100%);
    is_night 1.8% vs 34.9%. Plan: ablation test without is_external_ip in Step 4.

Step 4: Train the model

- [x] Step 4a/4b: Random Forest trained, time split (train before Oct 24,
  test after). Train 7256 rows (264 attacks), test 2856 rows (129 attacks).
  Model A (all features): 100% everywhere -> leakage via is_external_ip
  and severity_num. Model B (behaviour only): precision 0.992, recall
  0.984, FP=1, FN=2 (both early brute-force rows). Saved models/rf_model.joblib
  (model B + its feature list).
  Limits: 3 test incidents, no port scan in test, synthetic data optimistic.
- Next: Isolation Forest comparison (4c), then Task 2 correlation.

- [x] Step 4c: Isolation Forest (behaviour only, contamination=0.04):
  precision 0.785, recall 0.907, F1 0.842, FP=32, FN=12. Worse than RF
  (F1 0.988) but needs no labels. Decision: RF is primary detector.
- Task 1 DONE. Next: Task 2 correlation (src/correlate.py).

- [x] Step 5: correlate.py. GAP=30 min, group by source_ip+asset.
  11 incidents = 10 real + 1 FP (10.0.3.40). Graded vs scenario_id:
  no over-merge, no under-merge. Task 2 DONE.
- Next: Step 6 compliance mapping.

- [x] Step 6: compliance.py + config/compliance_map.json. Rule-based finding
  types (brute_force 3, port_scan 2, data_exfiltration 3,
  multi_stage_intrusion 2, low_confidence_anomaly 1). Task 3 DONE.
  Limitation: control mapping is my own illustrative judgment.


- [x] Step 7: connectors.py (CSV logs + AbuseIPDB, key optional) and
  app/main.py (FastAPI: /health, /analyze, /analyze/sample; Pydantic
  validation -> 422, 404/503/500 handling). Task 4 DONE.
  Limitation: window features only see the submitted batch.
- Next: Step 8 report.py, then README.

- [x] Step 8: report.py -> reports/security_report.html (sorted by risk,
  evidence, controls, remediation, metrics, limitations). Optional /report
  endpoint in the API. Task 5 report DONE.

- [x] Step 9: README. ALL TASKS DONE.

## Concepts learned
- Seed = reproducibility; leakage; accuracy misleading on imbalance
  (use precision/recall/F1); over- vs under-merging


## Metrics / Notes
(none yet)