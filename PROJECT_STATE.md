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


## Next
Step 3: preprocess.py (cleaning + features) -> train.py

    - Step 3a result: is_external_ip separates classes perfectly (0% vs 100%);
    is_night 1.8% vs 34.9%. Plan: ablation test without is_external_ip in Step 4.

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

## Concepts learned
- Seed = reproducibility; leakage; accuracy misleading on imbalance
  (use precision/recall/F1); over- vs under-merging


## Metrics / Notes
(none yet)