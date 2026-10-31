import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))


from services.risk_scoring import RiskScorer
from services.response_engine import ResponseEngine


# ==================================================
# Model Paths
# ==================================================

ANOMALY_MODEL_PATH = (
    BASE_DIR / "models" / "isolation_forest.pkl"
)

ATTACK_MODEL_PATH = (
    BASE_DIR / "models" / "attack_classifier.pkl"
)

ENCODER_PATH = (
    BASE_DIR / "models" / "attack_label_encoder.pkl"
)


# ==================================================
# Load Trained Models Once
# ==================================================

anomaly_model = joblib.load(
    ANOMALY_MODEL_PATH
)

attack_model = joblib.load(
    ATTACK_MODEL_PATH
)

encoder = joblib.load(
    ENCODER_PATH
)


# ==================================================
# Categorical Columns
# ==================================================

CATEGORICAL_COLUMNS = [
    "proto",
    "service",
    "state"
]

FEATURE_COLUMNS = None


# ==================================================
# Prepare Network Data
# ==================================================

def prepare_network_data(df):

    df = df.copy()

    columns_to_drop = [
        "id",
        "attack_cat",
        "label"
    ]

    for column in columns_to_drop:

        if column in df.columns:

            df = df.drop(
                columns=[column]
            )

    available_categorical = [
        column
        for column in CATEGORICAL_COLUMNS
        if column in df.columns
    ]

    df = pd.get_dummies(
        df,
        columns=available_categorical
    )

    global FEATURE_COLUMNS

    if FEATURE_COLUMNS is None:

        from services.preprocessing import prepare_data

        X_train, _, _, _, _, _ = prepare_data()

        FEATURE_COLUMNS = list(
            X_train.columns
        )

    df = df.reindex(
        columns=FEATURE_COLUMNS,
        fill_value=0
    )

    return df


# ==================================================
# Analyze Network Data
# ==================================================

def analyze_network_data(
    df,
    save_alerts=True
):

    if df.empty:

        raise ValueError(
            "Network data is empty."
        )

    total_records = len(df)

    print(
        f"Analyzing {total_records} network records..."
    )

    # --------------------------------------------------
    # 1. Prepare Data
    # --------------------------------------------------

    prepared_data = prepare_network_data(
        df
    )

    print(
        f"Prepared data shape: {prepared_data.shape}"
    )

    # --------------------------------------------------
    # 2. Isolation Forest
    # --------------------------------------------------

    print(
        "Running anomaly detection..."
    )

    anomaly_predictions = (
        anomaly_model.predict(
            prepared_data
        )
    )

    anomaly_flags = (
        anomaly_predictions == -1
    )

    # --------------------------------------------------
    # 3. XGBoost Attack Classification
    # --------------------------------------------------

    print(
        "Running attack classification..."
    )

    probabilities = (
        attack_model.predict_proba(
            prepared_data
        )
    )

    predicted_indices = np.argmax(
        probabilities,
        axis=1
    )

    attack_types = (
        encoder.inverse_transform(
            predicted_indices
        )
    )

    confidences = np.max(
        probabilities,
        axis=1
    )

    # --------------------------------------------------
    # 4. Risk + Response
    # --------------------------------------------------

    print(
        "Calculating risk scores..."
    )

    scorer = RiskScorer()
    response_engine = ResponseEngine()

    results = []

    for index in range(
        total_records
    ):

        result = scorer.assess(
            bool(
                anomaly_flags[index]
            ),
            attack_types[index],
            float(
                confidences[index]
            ),
            save=False
        )

        result[
            "recommended_response"
        ] = response_engine.get_response(
            result["attack_type"],
            result["severity"]
        )

        result[
            "record_number"
        ] = index + 1

        results.append(
            result
        )

        # --------------------------------------------------
        # Save alerts only when enabled
        # --------------------------------------------------

        if (
            save_alerts
            and
            result["anomaly"]
        ):

            scorer.alert_history.append(
                result
            )

    # --------------------------------------------------
    # Save alert history only when enabled
    # --------------------------------------------------

    if save_alerts:

        scorer.save_alert_history()

    print(
        f"Analysis completed for {len(results)} records."
    )

    return results