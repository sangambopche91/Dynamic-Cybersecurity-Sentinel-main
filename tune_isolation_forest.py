import sys
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from services.preprocessing import prepare_data


def tune_model():

    X_train, X_test, y_train, y_test, _, _ = prepare_data()

    # Use only normal traffic for training
    X_normal = X_train[y_train == 0]

    print("=" * 70)
    print("ISOLATION FOREST N_ESTIMATORS TUNING")
    print("=" * 70)

    print("\nNormal training records:", len(X_normal))
    print("Testing records:", len(X_test))

    # Best contamination found in previous experiment
    contamination = 0.30

    # Test different numbers of trees
    n_estimators_values = [
        100,
        200,
        300,
        500
    ]

    results = []

    for n_estimators in n_estimators_values:

        print("\n" + "-" * 70)
        print("Testing n_estimators:", n_estimators)
        print("Contamination:", contamination)

        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )

        # Train only on normal traffic
        model.fit(X_normal)

        # Predict testing data
        raw_predictions = model.predict(X_test)

        # Isolation Forest:
        #  1  = normal
        # -1  = anomaly
        #
        # Dataset:
        #  0  = normal
        #  1  = attack

        predictions = [
            1 if prediction == -1 else 0
            for prediction in raw_predictions
        ]

        accuracy = accuracy_score(y_test, predictions)

        precision = precision_score(
            y_test,
            predictions,
            zero_division=0
        )

        recall = recall_score(
            y_test,
            predictions,
            zero_division=0
        )

        f1 = f1_score(
            y_test,
            predictions,
            zero_division=0
        )

        results.append(
            (
                n_estimators,
                accuracy,
                precision,
                recall,
                f1
            )
        )

        print(f"Accuracy : {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall   : {recall:.4f}")
        print(f"F1 Score : {f1:.4f}")

    # Select best model based on F1
    best_result = max(
        results,
        key=lambda x: x[4]
    )

    print("\n" + "=" * 70)
    print("N_ESTIMATORS TUNING RESULTS")
    print("=" * 70)

    print(
        "\nn_estimators | Accuracy | Precision | Recall | F1"
    )

    print("-" * 60)

    for result in results:

        n_estimators, accuracy, precision, recall, f1 = result

        print(
            f"{n_estimators:^12} | "
            f"{accuracy:^8.4f} | "
            f"{precision:^9.4f} | "
            f"{recall:^6.4f} | "
            f"{f1:^6.4f}"
        )

    print("\n" + "=" * 70)
    print("BEST RESULT")
    print("=" * 70)

    print("Best n_estimators:", best_result[0])
    print("Accuracy :", best_result[1])
    print("Precision:", best_result[2])
    print("Recall   :", best_result[3])
    print("F1 Score :", best_result[4])


if __name__ == "__main__":
    tune_model()