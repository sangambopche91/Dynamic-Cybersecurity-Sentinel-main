import sys
from pathlib import Path
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_class_weight
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from services.preprocessing import prepare_data
# Load and preprocess the data
X_train, X_test, y_train, y_test, attack_train, attack_test = prepare_data()

# Encode attack categories into numbers
encoder = LabelEncoder()

attack_train_encoded = encoder.fit_transform(attack_train)
classes = np.unique(attack_train_encoded)

class_weights = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=attack_train_encoded
)

class_weights = dict(zip(classes, class_weights))

# Reduce the strength of the balanced weights
class_weights = {
    cls: 1 + 0.25 * (weight - 1)
    for cls, weight in class_weights.items()
}


attack_test_encoded = encoder.transform(attack_test)

print("Attack categories:")
print(encoder.classes_)

print("\nEncoded training labels:")
print(attack_train_encoded[:10])

# Split training data into training and validation sets
from sklearn.model_selection import train_test_split

X_train_split, X_val, y_train_split, y_val = train_test_split(
    X_train,
    attack_train_encoded,
    test_size=0.2,
    random_state=42,
    stratify=attack_train_encoded
)
# Create sample weights for the training split
sample_weights = np.array([
    class_weights[label]
    for label in y_train_split
])

# Hyperparameter search space
param_grid = {
    "n_estimators": [100, 200, 300],
    "max_depth": [None, 20, 30],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4],
    "max_features": ["sqrt", "log2"],
    "class_weight":  ["balanced"]
}
"""
# Create Randomized Search
search = RandomizedSearchCV(
    estimator=ExtraTreesClassifier(
        random_state=42,
        n_jobs=-1
    ),
    param_distributions=param_grid,
    n_iter=5,
    scoring="f1_macro",
    cv=2,
    random_state=42,
    n_jobs=-1,
    verbose=1
)

print("\n===== STARTING HYPERPARAMETER TUNING =====")

search.fit(X_train_split, y_train_split)

print("\n===== BEST PARAMETERS =====")
print(search.best_params_)

print("\nBest validation Macro F1:", search.best_score_)
"""

# Create XGBoost classifier
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    min_child_weight=1,
    gamma=0,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="multi:softprob",
    num_class=len(encoder.classes_),
    eval_metric="mlogloss",
    random_state=42,
    n_jobs=-1
)


print("\n===== USING XGBOOST =====")
print(model)

print("\nTraining XGBoost classifier...")

model.fit(
    X_train_split,
    y_train_split,
    sample_weight=sample_weights,
    verbose=False
)

print("Model training completed successfully.")

# Make predictions on validation data
val_probabilities = model.predict_proba(X_val)
val_predictions = np.argmax(val_probabilities, axis=1)

print("\n===== VALIDATION RESULTS =====")

print("Accuracy:", accuracy_score(y_val, val_predictions))

print(
    classification_report(
        y_val,
        val_predictions,
        labels=range(len(encoder.classes_)),
        target_names=encoder.classes_
    )
)
print("\n===== VALIDATION CONFUSION MATRIX =====")

print(confusion_matrix(y_val, val_predictions))





# Make predictions on validation data

print("\nMaking predictions on official test data...")

test_probabilities = model.predict_proba(X_test)
test_predictions = np.argmax(test_probabilities, axis=1)

print("Official test predictions completed.")

print("Predictions completed successfully.")


from sklearn.metrics import accuracy_score, classification_report, confusion_matrix



print("\n===== OFFICIAL TEST CLASSIFICATION REPORT =====")

print(
    classification_report(
        attack_test_encoded,
        test_predictions,
        labels=range(len(encoder.classes_)),
        target_names=encoder.classes_
    )
)

print("\n===== OFFICIAL TEST CONFUSION MATRIX =====")

print(confusion_matrix(attack_test_encoded, test_predictions))

import joblib

joblib.dump(model, "models/attack_classifier.pkl")
joblib.dump(encoder, "models/attack_label_encoder.pkl")