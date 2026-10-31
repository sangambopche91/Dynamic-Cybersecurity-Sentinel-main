from collections import deque
import numpy as np


class LiveBaseline:
    """
    Learns normal behavior from recently observed
    live network flows.
    """

    def __init__(self, max_samples=200):
        self.max_samples = max_samples
        self.samples = deque(maxlen=max_samples)

    def add_flow(self, features):
        """
        Add a live flow to the baseline.
        """

        values = self._extract_numeric_features(features)

        if values is not None:
            self.samples.append(values)

    def _extract_numeric_features(self, features):
        """
        Extract normalized traffic characteristics.
        """

        keys = [
            "dur",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
            "rate",
            "sload",
            "dload",
            "sinpkt",
            "dinpkt",
            "smean",
            "dmean",
            "swin",
            "dwin",
        ]

        values = []

        for key in keys:

            try:
                value = float(
                    features.get(key, 0)
                )

            except (TypeError, ValueError):
                value = 0.0

            if not np.isfinite(value):
                value = 0.0

            values.append(value)

        return np.array(
            values,
            dtype=float
        )

    def is_ready(self, minimum_samples=10):
        """
        Baseline becomes active after enough
        live samples have been collected.
        """

        return (
            len(self.samples)
            >= minimum_samples
        )

    def get_statistics(self):
        """
        Calculate mean and standard deviation
        for every feature.
        """

        if not self.samples:
            return None

        data = np.array(
            self.samples,
            dtype=float
        )

        mean = np.mean(
            data,
            axis=0
        )

        std = np.std(
            data,
            axis=0
        )

        std[std < 1e-6] = 1e-6

        return {
            "mean": mean,
            "std": std,
            "samples": len(self.samples)
        }

    def calculate_deviation(self, features):
        """
        Calculate normalized deviation of a
        new flow from the learned baseline.
        """

        if not self.is_ready():
            return 0.0

        statistics = self.get_statistics()

        if statistics is None:
            return 0.0

        current = (
            self._extract_numeric_features(
                features
            )
        )

        if current is None:
            return 0.0

        mean = statistics["mean"]
        std = statistics["std"]

        z_scores = np.abs(
            (current - mean) / std
        )

        # Ignore extreme numerical values so that
        # one feature does not dominate the score.
        z_scores = np.clip(
            z_scores,
            0,
            10
        )

        # Use the median instead of the mean.
        # This prevents large network features such
        # as sload/dload from dominating the score.
        deviation = float(
            np.median(z_scores)
        )

        return deviation