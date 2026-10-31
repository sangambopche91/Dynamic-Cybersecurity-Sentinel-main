import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

TRAIN_PATH = BASE_DIR / "data" / "unsw_nb15" / "UNSW_NB15_training-set.csv"
TEST_PATH = BASE_DIR / "data" / "unsw_nb15" / "UNSW_NB15_testing-set.csv"


def load_data():
    train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)

    return train_df, test_df


if __name__ == "__main__":
    train, test = load_data()

    print("Training shape:", train.shape)
    print("Testing shape:", test.shape)

    print("\nTraining columns:")
    print(train.columns.tolist())

    print("\nTraining preview:")
    print(train.head())