# Step 4a: Train the Random Forest

"""Train and evaluate a Random Forest for suspicious-event detection."""
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from preprocess import load_and_clean, add_basic_features, add_window_features

EVENT_TYPES = ["login_success", "login_failed", "file_access", "data_transfer",
               "config_change", "service_restart", "port_probe",
               "privilege_escalation"]
NUMERIC = ["hour", "is_night", "is_external_ip", "log_bytes_out",
           "severity_num", "fails_5min", "events_1min", "distinct_ports_1min"]
FEATURES = NUMERIC + [f"ev_{e}" for e in EVENT_TYPES]
CUTOFF = pd.Timestamp("2026-10-24")      # train before, test after


def build_features(df):
    df = add_window_features(add_basic_features(df))
    for e in EVENT_TYPES:                # fixed columns -> API can reuse
        df[f"ev_{e}"] = (df["event_type"] == e).astype(int)
    return df


if __name__ == "__main__":
    df = build_features(load_and_clean("data/raw/security_logs.csv"))
    os.makedirs("data/processed", exist_ok=True)
    df.to_csv("data/processed/features.csv", index=False)

    train, test = df[df.timestamp < CUTOFF], df[df.timestamp >= CUTOFF]
    print("Train:", len(train), "attacks:", train.is_suspicious.sum())
    print("Test: ", len(test), "attacks:", test.is_suspicious.sum())

    # model = RandomForestClassifier(n_estimators=200, class_weight="balanced",
    #                                random_state=42, n_jobs=-1)
    # model.fit(train[FEATURES], train["is_suspicious"])

    # pred = model.predict(test[FEATURES])
    # print(classification_report(test["is_suspicious"], pred, digits=3))
    # print("Confusion matrix [[TN FP] [FN TP]]:")
    # print(confusion_matrix(test["is_suspicious"], pred))

    # test = test.assign(pred=pred)
    # print("\nRecall per attack type (test period):")
    # for a, g in test[test.is_suspicious == 1].groupby("attack_type"):
    #     print(f"  {a}: {g.pred.mean():.2f} ({len(g)} rows)")

    # imp = pd.Series(model.feature_importances_, index=FEATURES)
    # print("\nTop features:\n", imp.sort_values(ascending=False).head(6).round(3))


    def run(name, feats, save=False):
        m = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                   random_state=42, n_jobs=-1)
        m.fit(train[feats], train["is_suspicious"])
        p = m.predict(test[feats])
        print(f"\n===== {name} =====")
        print(classification_report(test["is_suspicious"], p, digits=3))
        print("Confusion matrix [[TN FP] [FN TP]]:")
        print(confusion_matrix(test["is_suspicious"], p))
        t = test.assign(pred=p)
        print("Recall per attack type:")
        for a, g in t[t.is_suspicious == 1].groupby("attack_type"):
            print(f"  {a}: {g.pred.mean():.2f} ({len(g)} rows)")
        imp = pd.Series(m.feature_importances_, index=feats)
        print("Top features:\n", imp.sort_values(ascending=False).head(5).round(3))
        return m

    LEAKY = ["is_external_ip", "severity_num"]
    BEHAVIOUR = [f for f in FEATURES if f not in LEAKY]

    model_full = run("A) All features", FEATURES)
    model = run("B) Behaviour only (no is_external_ip, no severity_num)", BEHAVIOUR)
    FEATURES = BEHAVIOUR          # the honest model is the one we save    


# Step 4c: Isolation Forest (unsupervised comparison)
    
    from sklearn.ensemble import IsolationForest
    iso = IsolationForest(n_estimators=200, contamination=0.04,
                          random_state=42, n_jobs=-1)
    iso.fit(train[BEHAVIOUR])                       # labels are NOT used
    ip = (iso.predict(test[BEHAVIOUR]) == -1).astype(int)   # -1 = anomaly
    print("\n===== C) Isolation Forest (unsupervised, behaviour only) =====")
    print(classification_report(test["is_suspicious"], ip, digits=3))
    print("Confusion matrix [[TN FP] [FN TP]]:")
    print(confusion_matrix(test["is_suspicious"], ip))    



    os.makedirs("models", exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES}, "models/rf_model.joblib")




