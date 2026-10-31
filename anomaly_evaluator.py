import sys
from pathlib import Path

import joblib
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from services.preprocessing import prepare_data


MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"


def evaluate_model():

    X_train, X_test, y_train, y_test, _, _ = prepare_data()

    # Load trained Isolation Forest
    model = joblib.load(MODEL_PATH)

    print("Running predictions on testing data...")

    predictions = model.predict(X_test)

    # Isolation Forest:
    #  1  = normal
    # -1  = anomaly
    #
    # Our dataset:
    #  0  = normal
    #  1  = attack

    predictions = [1 if prediction == -1 else 0 for prediction in predictions]

    print("\n===== MODEL RESULTS =====")

    print("Accuracy :", accuracy_score(y_test, predictions))
    print("Precision:", precision_score(y_test, predictions, zero_division=0))
    print("Recall   :", recall_score(y_test, predictions, zero_division=0))
    print("F1 Score :", f1_score(y_test, predictions, zero_division=0))

    print("\n===== CONFUSION MATRIX =====")
    print(confusion_matrix(y_test, predictions))

    print("\n===== CLASSIFICATION REPORT =====")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Normal", "Attack"],
            zero_division=0
        )
    )


if __name__ == "__main__":
    evaluate_model()