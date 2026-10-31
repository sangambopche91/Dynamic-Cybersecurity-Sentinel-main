
from datetime import datetime
import json
from pathlib import Path


# ==========================================
# Project Root Directory
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ==========================================
# Alert History File
# ==========================================

ALERT_FILE = BASE_DIR / "alerts" / "alerts.json"


class RiskScorer:

    def __init__(self):

        # ==========================================
        # Base Risk Values
        # ==========================================

        self.base_risk = {
            "Normal": 0,
            "Analysis": 55,
            "Reconnaissance": 60,
            "Fuzzers": 65,
            "Generic": 70,
            "Exploits": 80,
            "DoS": 85,
            "Backdoor": 90,
            "Shellcode": 90,
            "Worms": 95,
            "Unknown Anomaly": 50
        }

        # Load previous alerts from alerts.json
        self.alert_history = self.load_alert_history()


    # ==========================================
    # Calculate Risk Score
    # ==========================================

    def calculate_risk(
        self,
        anomaly,
        attack_type,
        confidence
    ):

        if not anomaly:
            return 0

        if attack_type == "Normal":
            return 50

        base = self.base_risk.get(
            attack_type,
            50
        )

        risk = base * (
            0.5 + 0.5 * confidence
        )

        risk = max(
            0,
            min(100, risk)
        )

        return round(risk)


    # ==========================================
    # Determine Severity
    # ==========================================

    def get_severity(
        self,
        risk_score
    ):

        if risk_score <= 30:
            return "Low"

        elif risk_score <= 60:
            return "Medium"

        elif risk_score <= 80:
            return "High"

        else:
            return "Critical"


    # ==========================================
    # Generate Security Alert
    # ==========================================

    def generate_alert(
        self,
        attack_type,
        confidence,
        risk_score,
        severity
    ):

        if severity == "Low":
            return "No immediate threat detected."

        confidence_percent = confidence * 100

        return (
            f"SECURITY ALERT | "
            f"Attack: {attack_type} | "
            f"Confidence: {confidence_percent:.0f}% | "
            f"Risk Score: {risk_score} | "
            f"Severity: {severity}"
        )


    # ==========================================
    # Load Alert History
    # ==========================================

    def load_alert_history(self):

        # If alerts.json does not exist,
        # start with an empty alert history.

        if not ALERT_FILE.exists():
            return []

        try:

            with open(
                ALERT_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            # Make sure the JSON contains a list.
            if isinstance(data, list):
                return data

            return []

        except (
            json.JSONDecodeError,
            OSError,
            TypeError
        ):

            return []


    # ==========================================
    # Save Alert History
    # ==========================================

    def save_alert_history(self):

        ALERT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            ALERT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                self.alert_history,
                file,
                indent=4
            )


    # ==========================================
    # Complete Risk Assessment
    # ==========================================

    def assess(
        self,
        anomaly,
        attack_type,
        confidence,
        save=True
    ):

        if anomaly and attack_type == "Normal":
            attack_type = "Unknown Anomaly"

        risk_score = self.calculate_risk(
            anomaly,
            attack_type,
            confidence
        )

        severity = self.get_severity(
            risk_score
        )

        alert = self.generate_alert(
            attack_type,
            confidence,
            risk_score,
            severity
        )

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        alert_record = {
            "timestamp": timestamp,
            "anomaly": bool(anomaly),
            "attack_type": attack_type,
            "confidence": float(confidence),
            "risk_score": risk_score,
            "severity": severity,
            "alert": alert
        }

        # Save only when requested.
        if save:

            self.alert_history.append(
                alert_record
            )

            self.save_alert_history()

        return alert_record


    # ==========================================
    # Get Alert History
    # ==========================================

    def get_alert_history(self):

        return self.alert_history

