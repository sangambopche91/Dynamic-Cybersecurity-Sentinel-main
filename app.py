from flask import Flask, render_template, request, jsonify

from services.risk_scoring import RiskScorer
from services.prediction_service import analyze_csv
from services.v2.live_monitor import live_monitor

import tempfile
import os


app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


@app.route("/")
def home():

    # Load the latest alert history from disk
    # every time the dashboard is opened.
    scorer = RiskScorer()

    all_alerts = scorer.get_alert_history()

    recent_alerts = all_alerts[-10:]

    # Get current live monitoring status
    live_status = live_monitor.get_status()

    return render_template(
        "dashboard.html",
        alerts=recent_alerts,
        all_alerts=all_alerts,
        live_status=live_status
    )


@app.route("/upload", methods=["POST"])
def upload_file():

    if "file" not in request.files:
        return "No file uploaded", 400

    file = request.files["file"]

    if file.filename == "":
        return "No file selected", 400

    if not file.filename.lower().endswith(".csv"):
        return "Only CSV files are allowed", 400

    temp_path = None

    try:

        # Save uploaded CSV temporarily
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".csv"
        ) as temp_file:

            file.save(temp_file.name)
            temp_path = temp_file.name

        # Run uploaded data through the common ML pipeline
        results = analyze_csv(temp_path)

        return render_template(
            "results.html",
            results=results,
            total_records=len(results)
        )

    except Exception as e:

        return render_template(
            "error.html",
            message=str(e)
        ), 400

    finally:

        # Remove temporary uploaded file
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@app.route("/live/start", methods=["POST"])
def start_live_monitoring():

    started = live_monitor.start()

    if started:
        return jsonify({
            "success": True,
            "message": "Live network monitoring started.",
            "status": live_monitor.get_status()
        })

    return jsonify({
        "success": False,
        "message": "Live network monitoring is already running.",
        "status": live_monitor.get_status()
    })


@app.route("/live/stop", methods=["POST"])
def stop_live_monitoring():

    stopped = live_monitor.stop()

    if stopped:
        return jsonify({
            "success": True,
            "message": "Live network monitoring stop requested.",
            "status": live_monitor.get_status()
        })

    return jsonify({
        "success": False,
        "message": "Live network monitoring is not running.",
        "status": live_monitor.get_status()
    })


@app.route("/live/status", methods=["GET"])
def live_status():

    return jsonify(
        live_monitor.get_status()
    )
@app.route("/live/alerts", methods=["GET"])
def live_alerts():
    scorer = RiskScorer()
    all_alerts = scorer.get_alert_history()

    # Return the latest 20 alerts
    recent_alerts = all_alerts[-20:]

    return jsonify(recent_alerts)

@app.errorhandler(413)
def request_entity_too_large(error):

    return render_template(
        "error.html",
        message="The uploaded file is too large. Please upload a CSV file smaller than 50 MB."
    ), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)