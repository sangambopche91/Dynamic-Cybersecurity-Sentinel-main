from pathlib import Path
import sys

import pandas as pd


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)

if str(BASE_DIR) not in sys.path:

    sys.path.insert(
        0,
        str(BASE_DIR)
    )


from services.ml_engine import (
    analyze_network_data
)

from services.v2.flow_schema import (
    NetworkFlow
)

from services.v2.fake_live_source import (
    generate_flow
)


def analyze_live_flow(
    flow: NetworkFlow
):
    """
    Analyze one live network flow using
    the same ML engine used by V1.

    Live analysis does NOT directly save
    alerts. The live pipeline applies the
    baseline calibration first.
    """

    if not isinstance(
        flow,
        NetworkFlow
    ):

        raise TypeError(
            "analyze_live_flow() expects "
            "a NetworkFlow object."
        )

    # Convert live flow into the same
    # DataFrame format used by V1.

    df = pd.DataFrame(
        [flow.to_dict()]
    )

    # Run the common ML engine but DO NOT
    # save the raw ML anomaly as an alert.

    results = analyze_network_data(
        df,
        save_alerts=False
    )

    return results[0]


# ==================================================
# Standalone Test
# ==================================================

if __name__ == "__main__":

    print("=" * 70)
    print("DYNAMIC CYBERSECURITY SENTINEL")
    print("V2 LIVE ANALYZER TEST")
    print("=" * 70)

    print(
        "\nGenerating one live network flow..."
    )

    flow = generate_flow()

    print(
        "Flow generated successfully."
    )

    print(
        "\nSending live flow to common ML engine..."
    )

    result = analyze_live_flow(
        flow
    )

    print(
        "\nLive analysis successful!"
    )

    print(
        "\nResult:"
    )

    print(
        result
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "V2 LIVE ANALYZER TEST COMPLETED"
    )

    print(
        "=" * 70
    )