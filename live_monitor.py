from threading import Thread, Lock

from services.v2.live_pipeline import LivePipeline


class LiveMonitor:
    """
    Manages the V2 real-time network monitoring pipeline.

    Flask can use this class to:
    - start monitoring
    - stop monitoring
    - check monitoring status
    - read live statistics
    """

    def __init__(self):

        self.pipeline = None
        self.thread = None
        self.running = False

        self.lock = Lock()

    def start(self):

        with self.lock:

            if self.running:
                return False

            self.pipeline = LivePipeline(
                capture_window=5,
                flow_timeout=5
            )

            self.running = True

            self.thread = Thread(
                target=self._run_pipeline,
                daemon=True
            )

            self.thread.start()

            return True

    def _run_pipeline(self):

        try:

            self.pipeline.run()

        except Exception as error:

            print("Live monitoring error:")
            print(error)

        finally:

            with self.lock:
                self.running = False

    def stop(self):

        with self.lock:

            if not self.running:
                return False

            if self.pipeline is not None:

                # This now actually stops
                # the Scapy packet capture.
                self.pipeline.stop()

            self.running = False

            return True

    def get_status(self):

        with self.lock:

            if self.pipeline is None:

                return {
                    "running": False,
                    "total_packets": 0,
                    "total_flows_analyzed": 0,
                    "total_anomalies": 0
                }

            return {
                "running": self.running
                and self.pipeline.running,

                "total_packets":
                    self.pipeline.total_packets,

                "total_flows_analyzed":
                    self.pipeline.total_flows_analyzed,

                "total_anomalies":
                    self.pipeline.total_anomalies
            }


live_monitor = LiveMonitor()