from data_loader import load_data


def inspect_data():
    train_df, test_df = load_data()

    print("\n===== DATASET SHAPE =====")
    print("Training:", train_df.shape)
    print("Testing :", test_df.shape)

    print("\n===== COLUMNS =====")
    for i, column in enumerate(train_df.columns, start=1):
        print(f"{i}. {column}")

    print("\n===== DATA TYPES =====")
    print(train_df.dtypes)

    print("\n===== MISSING VALUES =====")
    print(train_df.isnull().sum())

    print("\n===== ATTACK CATEGORIES =====")
    print(train_df["attack_cat"].value_counts(dropna=False))

    print("\n===== NORMAL / ATTACK =====")
    print(train_df["label"].value_counts())

    print("\n===== SAMPLE DATA =====")
    print(train_df.head())


if __name__ == "__main__":
    inspect_data()