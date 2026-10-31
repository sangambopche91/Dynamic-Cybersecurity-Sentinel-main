import os
import sys

# Add project root to Python path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


from pathlib import Path

import pandas as pd

from services.ml_engine import analyze_network_data


BASE_DIR = Path(__file__).resolve().parent.parent

CSV_PATH = (
    BASE_DIR
    / "data"
    / "test_upload_100.csv"
)


print("=" * 70)
print("DYNAMIC CYBERSECURITY SENTINEL")
print("COMMON ML ENGINE TEST")
print("=" * 70)

print("\nLoading V1 test CSV...")

df = pd.read_csv(CSV_PATH)

print("Records:", len(df))
print("Columns:", len(df.columns))

print("\nSending data to common ML engine...")

results = analyze_network_data(df)

print("\nAnalysis successful!")

print("Results:", len(results))

if results:
    print("\nFirst result:")
    print(results[0])

print("\n" + "=" * 70)
print("COMMON ML ENGINE TEST COMPLETED")
print("=" * 70)