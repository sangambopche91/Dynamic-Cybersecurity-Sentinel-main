from pathlib import Path
import sys

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


import time
from threading import Event

from scapy.all import (
    AsyncSniffer,
    IP
)

from services.v2.flow_builder import (
    FlowBuilder
)

from services.v2.live_analyzer import (
    analyze_live_flow
)

from services.v2.live_baseline import (
    LiveBaseline
)

from services.v2.flow_schema import (
    NetworkFlow
)

from services.risk_scoring import (
    RiskScorer
)

from services.response_engine import (
    ResponseEngine
)


# ==================================================
# Configuration
# ==================================================

CAPTURE_WINDOW_SECONDS = 5

FLOW_TIMEOUT_SECONDS = 5

BASELINE_MINIMUM_SAMPLES = 10

BASELINE_DEVIATION_THRESHOLD = 3.0


# ==================================================
# Live Pipeline
# ==================================================

class LivePipeline:
    """
    Continuous real-time network monitoring.

    Flow:

    Real packets
        ↓
    Flow Builder
        ↓
    Isolation Forest
        ↓
    XGBoost
        ↓
    Live Baseline
        ↓
    Final anomaly decision
        ↓
    Risk Scoring
        ↓
    Alert History
    """

    def __init__(
        self,
        capture_window=CAPTURE_WINDOW_SECONDS,
        flow_timeout=FLOW_TIMEOUT_SECONDS
    ):

        self.capture_window = (
            capture_window
        )

        self.flow_timeout = (
            flow_timeout
        )

        self.builder = FlowBuilder()

        self.baseline = LiveBaseline(
            max_samples=200
        )

        self.total_packets = 0

        self.total_flows_analyzed = 0

        self.total_anomalies = 0

        self.stop_event = Event()

        self.sniffer = None

        self.running = False


    # ==================================================
    # Packet Processing
    # ==================================================

    def process_packet(
        self,
        packet
    ):

        if IP not in packet:

            return

        self.total_packets += 1

        self.builder.add_packet(
            packet
        )


    # ==================================================
    # Expired Flows
    # ==================================================

    def flush_expired_flows(self):

        current_time = time.time()

        expired_keys = []

        for (
            flow_key,
            flow_data
        ) in list(
            self.builder.flows.items()
        ):

            if (
                flow_data["last_time"]
                is None
            ):

                continue

            inactive_time = (
                current_time
                -
                flow_data["last_time"]
            )

            if (
                inactive_time
                >= self.flow_timeout
            ):

                expired_keys.append(
                    flow_key
                )

        if not expired_keys:

            return

        print()
        print("=" * 70)
        print("EXPIRED FLOWS")
        print("=" * 70)

        print(
            "Flows ready for analysis:",
            len(expired_keys)
        )

        for flow_key in expired_keys:

            flow_data = (
                self.builder.flows.get(
                    flow_key
                )
            )

            if flow_data is None:

                continue

            self.analyze_flow(
                flow_data
            )

            del self.builder.flows[
                flow_key
            ]


    # ==================================================
    # Analyze One Flow
    # ==================================================

    def analyze_flow(
        self,
        flow_data
    ):

        try:

            # --------------------------------------------------
            # 1. Build features
            # --------------------------------------------------

            features = (
                self.builder.get_flow_features(
                    flow_data
                )
            )

            flow = NetworkFlow(
                **features
            )

            # --------------------------------------------------
            # 2. Baseline deviation
            # --------------------------------------------------

            baseline_deviation = (
                self.baseline.calculate_deviation(
                    features
                )
            )

            baseline_ready = (
                self.baseline.is_ready(
                    BASELINE_MINIMUM_SAMPLES
                )
            )

            # --------------------------------------------------
            # 3. Existing ML
            # --------------------------------------------------

            result = analyze_live_flow(
                flow
            )

            ml_anomaly = bool(
                result["anomaly"]
            )

            # --------------------------------------------------
            # 4. Final calibrated decision
            # --------------------------------------------------

            if not baseline_ready:

                # During learning we do not confirm
                # raw ML anomalies as live alerts.

                final_anomaly = False

            else:

                final_anomaly = (
                    ml_anomaly
                    and
                    baseline_deviation
                    >= BASELINE_DEVIATION_THRESHOLD
                )

            # --------------------------------------------------
            # 5. Learn only ML-normal traffic
            # --------------------------------------------------

            if not baseline_ready:
                self.baseline.add_flow(features)

            # --------------------------------------------------
            # 6. Calculate final risk
            # --------------------------------------------------

            scorer = RiskScorer()

            response_engine = (
                ResponseEngine()
            )

            calibrated_result = (
                scorer.assess(
                    final_anomaly,
                    result["attack_type"],
                    float(
                        result["confidence"]
                    ),
                    save=False
                )
            )

            calibrated_result[
                "recommended_response"
            ] = response_engine.get_response(
                calibrated_result[
                    "attack_type"
                ],
                calibrated_result[
                    "severity"
                ]
            )

            calibrated_result[
                "record_number"
            ] = (
                self.total_flows_analyzed
                + 1
            )

            calibrated_result[
                "ml_anomaly"
            ] = ml_anomaly

            calibrated_result[
                "baseline_deviation"
            ] = round(
                baseline_deviation,
                2
            )

            calibrated_result[
                "baseline_ready"
            ] = baseline_ready

            # --------------------------------------------------
            # 7. Save only final live anomalies
            # --------------------------------------------------

            if final_anomaly:

                scorer.alert_history.append(
                    calibrated_result
                )

                scorer.save_alert_history()

            # --------------------------------------------------
            # 8. Counters
            # --------------------------------------------------

            self.total_flows_analyzed += 1

            if final_anomaly:

                self.total_anomalies += 1

            # --------------------------------------------------
            # 9. Display
            # --------------------------------------------------

            print()
            print("LIVE ML RESULT")
            print("-" * 70)

            print(
                "Source      :",
                flow_data["src_ip"],
                ":",
                flow_data["src_port"]
            )

            print(
                "Destination :",
                flow_data["dst_ip"],
                ":",
                flow_data["dst_port"]
            )

            print(
                "Protocol    :",
                flow_data["proto"]
            )

            print(
                "Packets     :",
                flow_data["spkts"]
                +
                flow_data["dpkts"]
            )

            print(
                "Attack Type :",
                calibrated_result[
                    "attack_type"
                ]
            )

            print(
                "ML Anomaly  :",
                ml_anomaly
            )

            print(
                "Baseline    :",
                len(
                    self.baseline.samples
                ),
                "samples"
            )

            print(
                "Deviation   :",
                round(
                    baseline_deviation,
                    2
                )
            )

            print(
                "Baseline Status:",
                (
                    "READY"
                    if baseline_ready
                    else "LEARNING"
                )
            )

            print(
                "Final Anomaly:",
                final_anomaly
            )

            print(
                "Confidence  :",
                round(
                    result["confidence"],
                    4
                )
            )

            print(
                "Risk Score  :",
                calibrated_result[
                    "risk_score"
                ]
            )

            print(
                "Severity    :",
                calibrated_result[
                    "severity"
                ]
            )

            print(
                "Response    :",
                calibrated_result[
                    "recommended_response"
                ]
            )

        except Exception as error:

            print()
            print(
                "Flow analysis error:"
            )

            print(
                error
            )


    # ==================================================
    # Flush All Flows
    # ==================================================

    def flush_all_flows(self):

        remaining_flows = list(
            self.builder.flows.values()
        )

        if not remaining_flows:

            return

        print()
        print("=" * 70)
        print("FINAL FLOW ANALYSIS")
        print("=" * 70)

        for flow_data in (
            remaining_flows
        ):

            self.analyze_flow(
                flow_data
            )

        self.builder.flows.clear()


    # ==================================================
    # Stop
    # ==================================================

    def stop(self):

        print()
        print(
            "Stop signal received."
        )

        self.stop_event.set()

        if self.sniffer is not None:

            try:

                self.sniffer.stop()

            except Exception as error:

                print(
                    "Sniffer stop warning:",
                    error
                )

        self.running = False


    # ==================================================
    # Run
    # ==================================================

    def run(self):

        print("=" * 70)
        print("DYNAMIC CYBERSECURITY SENTINEL")
        print("V2 CONTINUOUS LIVE MONITORING")
        print("=" * 70)

        print()

        print(
            "Capture window:",
            self.capture_window,
            "seconds"
        )

        print(
            "Flow timeout:",
            self.flow_timeout,
            "seconds"
        )

        print(
            "Baseline samples required:",
            BASELINE_MINIMUM_SAMPLES
        )

        print(
            "Baseline deviation threshold:",
            BASELINE_DEVIATION_THRESHOLD
        )

        print()

        print(
            "Real network monitoring started."
        )

        print(
            "Press CTRL+C to stop."
        )

        print()

        self.stop_event.clear()

        self.running = True

        try:

            while not self.stop_event.is_set():

                self.sniffer = AsyncSniffer(
                    prn=self.process_packet,
                    store=False
                )

                self.sniffer.start()

                start_time = time.time()

                while (
                    time.time()
                    -
                    start_time
                    <
                    self.capture_window
                ):

                    if (
                        self.stop_event.is_set()
                    ):

                        break

                    time.sleep(
                        0.1
                    )

                if self.sniffer is not None:

                    try:

                        self.sniffer.stop()

                    except Exception:

                        pass

                    self.sniffer = None

                if (
                    not self.stop_event.is_set()
                ):

                    self.flush_expired_flows()

        except KeyboardInterrupt:

            print()
            print("=" * 70)
            print(
                "STOPPING LIVE MONITORING"
            )
            print("=" * 70)

            self.stop_event.set()

            if self.sniffer is not None:

                try:

                    self.sniffer.stop()

                except Exception:

                    pass

                self.sniffer = None

        finally:

            self.running = False

            self.flush_all_flows()

            print()
            print("=" * 70)
            print(
                "LIVE MONITORING SUMMARY"
            )
            print("=" * 70)

            print(
                "Total packets captured:",
                self.total_packets
            )

            print(
                "Total flows analyzed:",
                self.total_flows_analyzed
            )

            print(
                "Total calibrated anomalies:",
                self.total_anomalies
            )

            if (
                self.total_flows_analyzed
                > 0
            ):

                anomaly_rate = (
                    self.total_anomalies
                    /
                    self.total_flows_analyzed
                    *
                    100
                )

                print(
                    "Calibrated anomaly rate:",
                    round(
                        anomaly_rate,
                        1
                    ),
                    "%"
                )

            print(
                "Baseline samples learned:",
                len(
                    self.baseline.samples
                )
            )

            print(
                "Baseline status:",
                (
                    "READY"
                    if self.baseline.is_ready(
                        BASELINE_MINIMUM_SAMPLES
                    )
                    else "LEARNING"
                )
            )

            print()

            print(
                "Live monitoring stopped."
            )


# ==================================================
# Direct Execution
# ==================================================

if __name__ == "__main__":

    pipeline = LivePipeline(
        capture_window=5,
        flow_timeout=5
    )

    pipeline.run()