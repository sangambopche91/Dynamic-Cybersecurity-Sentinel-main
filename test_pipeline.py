import sys
from pathlib import Path

import joblib
import numpy as np


# ==========================================
# Project Root Directory
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))


# ==========================================
# Import Required Modules
# ==========================================

from services.preprocessing import prepare_data
from services.risk_scoring import RiskScorer


# ==========================================
# Load Models and Data
# ==========================================

X_train, X_test, y_train, y_test, attack_train, attack_test = prepare_data()

ANOMALY_MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"
ATTACK_MODEL_PATH = BASE_DIR / "models" / "attack_classifier.pkl"
ENCODER_PATH = BASE_DIR / "models" / "attack_label_encoder.pkl"

anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
attack_model = joblib.load(ATTACK_MODEL_PATH)
encoder = joblib.load(ENCODER_PATH)


# ==========================================
# Process One Network Record
# ==========================================

def process_record(sample, scorer=None):

    if scorer is None:
        scorer = RiskScorer()

    # ------------------------------------------
    # MEMBER 2 - Anomaly Detection
    # ------------------------------------------

    anomaly_prediction = anomaly_model.predict(sample)[0]

    anomaly = anomaly_prediction == -1


    # ------------------------------------------
    # MEMBER 3 - Attack Classification
    # ------------------------------------------

    probabilities = attack_model.predict_proba(sample)

    predicted_index = np.argmax(
        probabilities,
        axis=1
    )[0]

    attack_type = encoder.inverse_transform(
        [predicted_index]
    )[0]

    confidence = np.max(probabilities)


    # ------------------------------------------
    # MEMBER 4 - Risk Scoring
    # ------------------------------------------

    result = scorer.assess(
        anomaly,
        attack_type,
        confidence
    )

    return result


# ==========================================
# Test Multiple Network Records
# ==========================================

def run_test(number_of_records=10):

    samples = X_test.iloc[:number_of_records]

    scorer = RiskScorer()

    print("\n========================================")
    print("   DYNAMIC CYBERSECURITY SENTINEL")
    print("========================================")

    print(
        f"\nProcessing {number_of_records} network records..."
    )


    for i in range(len(samples)):

        sample = samples.iloc[[i]]

        result = process_record(
            sample,
            scorer
        )


        print("\n----------------------------------------")
        print(f"NETWORK RECORD {i + 1}")
        print("----------------------------------------")

        print("Anomaly:", result["anomaly"])
        print("Attack Type:", result["attack_type"])
        print(f"Confidence: {result['confidence']:.4f}")
        print("Risk Score:", result["risk_score"])
        print("Severity:", result["severity"])
        print("Alert:", result["alert"])


    # ==========================================
    # Display Alert History
    # ==========================================

    print("\n========================================")
    print("           ALERT HISTORY")
    print("========================================")

    history = scorer.get_alert_history()

    print(
        "\nTotal saved alerts:",
        len(history)
    )


    for i, alert in enumerate(
        history,
        start=1
    ):

        print(f"\nAlert {i}")
        print("Timestamp:", alert["timestamp"])
        print("Anomaly:", alert["anomaly"])
        print("Attack Type:", alert["attack_type"])
        print(f"Confidence: {alert['confidence']:.4f}")
        print("Risk Score:", alert["risk_score"])
        print("Severity:", alert["severity"])


    # ==========================================
    # Final Message
    # ==========================================

    print("\n========================================")
    print("       ALL RECORDS PROCESSED")
    print("       PIPELINE COMPLETED")
    print("========================================")


# ==========================================
# Run Test Only When File Is Executed
# ==========================================

if __name__ == "__main__":
    run_test()