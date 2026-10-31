from pathlib import Path
import sys
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.input_validator import validate_csv
from services.ml_engine import analyze_network_data


def analyze_csv(file_path):
    """
    V1 CSV analysis entry point.

    Validates and loads the uploaded CSV, then sends
    the network data to the common ML engine used by
    both CSV and future live-server analysis.
    """

    # Step 1: Validate CSV
    validation = validate_csv(file_path)

    if not validation["valid"]:
        missing = ", ".join(validation["missing_features"])

        raise ValueError(
            validation["message"]
            + f" Missing features: {missing}"
        )

    # Step 2: Load CSV
    df = pd.read_csv(file_path)

    if df.empty:
        raise ValueError("The uploaded CSV file is empty.")

    # Step 3: Send data to the common ML engine
    results = analyze_network_data(df)

    return results