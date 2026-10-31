from pathlib import Path

import pandas as pd


# These are the network features required by the
# currently trained Isolation Forest and XGBoost models.
REQUIRED_FEATURES = [
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
]


def validate_csv(file_path):
    """
    Validate an uploaded CSV before sending it
    to the machine-learning pipeline.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise ValueError("The uploaded file could not be found.")

    if file_path.suffix.lower() != ".csv":
        raise ValueError("Only CSV files are supported.")

    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        raise ValueError(
            f"The CSV file could not be read: {str(e)}"
        )

    if df.empty:
        raise ValueError("The uploaded CSV file is empty.")

    # Find required features that are missing.
    missing_features = [
        feature
        for feature in REQUIRED_FEATURES
        if feature not in df.columns
    ]

    if missing_features:
        return {
            "valid": False,
            "message": (
                "The uploaded file does not contain enough "
                "network traffic information for the current "
                "ML models."
            ),
            "missing_features": missing_features,
            "total_records": len(df),
            "total_columns": len(df.columns),
        }

    return {
        "valid": True,
        "message": "CSV format is compatible with the Sentinel ML pipeline.",
        "missing_features": [],
        "total_records": len(df),
        "total_columns": len(df.columns),
        "extra_columns": [
            column
            for column in df.columns
            if column not in REQUIRED_FEATURES
        ],
    }


if __name__ == "__main__":

    test_file = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "test_upload_100.csv"
    )

    print("=" * 60)
    print("DYNAMIC CYBERSECURITY SENTINEL")
    print("CSV INPUT VALIDATION TEST")
    print("=" * 60)

    result = validate_csv(test_file)

    print("\nValidation result:")
    print("Valid:", result["valid"])
    print("Message:", result["message"])
    print("Records:", result["total_records"])
    print("Columns:", result["total_columns"])

    if result["missing_features"]:
        print("\nMissing features:")
        for feature in result["missing_features"]:
            print("-", feature)

    if result.get("extra_columns"):
        print("\nExtra columns detected:")
        for column in result["extra_columns"]:
            print("-", column)

    print("\n" + "=" * 60)