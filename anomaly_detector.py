import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from services.preprocessing import prepare_data


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"


def train_anomaly_model():

    X_train, X_test, y_train, y_test, _, _ = prepare_data()

    # Use only normal traffic for learning normal behavior
    X_normal = X_train[y_train == 0]

    print("Normal training records:", len(X_normal))

    model = IsolationForest(
        n_estimators=100,
        contamination=0.30,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_normal)

    joblib.dump(model, MODEL_PATH)

    print("\nIsolation Forest trained successfully.")
    print("Model saved to:", MODEL_PATH)

    return model


def predict_anomaly(model, X):
    predictions = model.predict(X)

    # Isolation Forest:
    # 1  = normal
    # -1 = anomaly

    anomaly = predictions[0] == -1

    return anomaly


if __name__ == "__main__":
     train_anomaly_model()
    
    