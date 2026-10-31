import sys
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from services.data_loader import load_data


CATEGORICAL_COLUMNS = [
    "proto",
    "service",
    "state"
]


def prepare_data():
    train_df, test_df = load_data()

    # Separate target columns
    y_train = train_df["label"]
    y_test = test_df["label"]

    attack_train = train_df["attack_cat"]
    attack_test = test_df["attack_cat"]

    # Remove columns that should not be model inputs
    columns_to_drop = ["id", "attack_cat", "label"]

    X_train = train_df.drop(columns=columns_to_drop)
    X_test = test_df.drop(columns=columns_to_drop)

    # Convert categorical columns to numerical representation
    X_train = pd.get_dummies(
        X_train,
        columns=CATEGORICAL_COLUMNS
    )

    X_test = pd.get_dummies(
        X_test,
        columns=CATEGORICAL_COLUMNS
    )

    # Make sure train and test have identical columns
    X_train, X_test = X_train.align(
        X_test,
        join="left",
        axis=1,
        fill_value=0
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test,
        attack_train,
        attack_test
    )


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, attack_train, attack_test = prepare_data()

    print("===== PREPROCESSING RESULT =====")

    print("X_train shape:", X_train.shape)
    print("X_test shape :", X_test.shape)

    print("\nTraining labels:")
    print(y_train.value_counts())

    print("\nTesting labels:")
    print(y_test.value_counts())

    print("\nFeature data types:")
    print(X_train.dtypes.value_counts())

    print("\nFirst 5 rows:")
    print(X_train.head())