from datetime import datetime, timezone
import json
from pathlib import Path

from flask import Flask, Response, jsonify, request
from flask_cors import CORS

from scanner.adapter_manager import read_adapter_status
from scanner.network_reader import read_networks
from scanner.scanner_service import (
    read_scanner_status,
    start_scanner,
    stop_scanner,
)
from packet_capture.packet_reader import read_packet_feed
from packet_capture.capture_service import (
    read_capture_status,
    start_capture,
    stop_capture,
)
import csv
import io
import os
from ml.inference_service import create_v3_inference_service
from data.incident_store import (
    get_incidents,
    save_pcap_analysis,
    get_pcap_analyses,
    get_pcap_analysis_by_id,
    save_ml_test_run,
    get_ml_test_runs,
    get_ml_test_run_by_id,
)
from ml.pcap_analyzer import analyze_pcap_file
from ml.evaluation_service import (
    evaluate_test_dataset,
    list_available_test_datasets,
)
from ml.v3_feature_schema import V3_FEATURE_NAMES, V3_FEATURE_COUNT
from reports.report_service import (
    generate_csv_report,
    generate_pdf_report,
    get_report_summary,
)
from ml.wifi_recommendation.inference_service import classify_and_recommend_networks
from ml.wifi_recommendation.evaluation_service import get_recommendation_model_metadata
from ml.wifi_recommendation.wifi_connector import attempt_wifi_connection


app = Flask(__name__)
CORS(app)

ml_service = create_v3_inference_service()

ML_LIVE_STATUS_JSON = (
    Path(__file__).resolve().parent
    / "data"
    / "packet_logs"
    / "ml_live_status.json"
)


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "message": "NetShield backend is running",
        }
    )


@app.get("/api/interfaces")
def interfaces():
    return jsonify(read_adapter_status())


@app.get("/api/networks")
def networks():
    network_rows = read_networks()

    return jsonify(
        {
            "count": len(network_rows),
            "networks": network_rows,
        }
    )



@app.get("/api/scanner/status")
def scanner_status():
    return jsonify(read_scanner_status())


@app.post("/api/scanner/start")
def scanner_start():
    data = request.get_json(silent=True) or {}

    response, status_code = start_scanner(
        data.get("interface")
    )

    return jsonify(response), status_code


@app.post("/api/scanner/stop")
def scanner_stop():
    response, status_code = stop_scanner()

    return jsonify(response), status_code



@app.get("/api/packets")
def packets():
    limit = request.args.get(
        "limit",
        default=50,
        type=int,
    )

    return jsonify(
        read_packet_feed(limit=limit)
    )


@app.get("/api/capture/status")
def capture_status():
    return jsonify(read_capture_status())


@app.post("/api/capture/start")
def capture_start():
    data = request.get_json(silent=True) or {}

    response, status_code = start_capture(
        data.get("interface")
    )

    return jsonify(response), status_code


@app.post("/api/capture/stop")
def capture_stop():
    response, status_code = stop_capture()

    return jsonify(response), status_code


@app.get("/api/ml/status")
def ml_status():
    return jsonify(
        {
            "status": "ok",
            "model": "random_forest_awid3_v3_expanded",
            "feature_count": 31,
        }
    )


@app.post("/api/ml/analyze-window")
def ml_analyze_window():
    data = request.get_json(silent=True) or {}

    if (
        not isinstance(data, dict)
        or "packets" not in data
        or not isinstance(data["packets"], list)
    ):
        return (
            jsonify(
                {
                    "error": "Request body must be a JSON object with a 'packets' list."
                }
            ),
            400,
        )

    try:
        result = ml_service.analyze_window(data["packets"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


@app.get("/api/ml/live-status")
def ml_live_status():
    if not ML_LIVE_STATUS_JSON.exists():
        return jsonify({"status": "no_inference"})

    try:
        payload = json.loads(
            ML_LIVE_STATUS_JSON.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return jsonify({"status": "no_inference"})

    if not isinstance(payload, dict):
        return jsonify({"status": "no_inference"})

    return jsonify(payload)


@app.get("/api/incidents")
def incidents():
    incident_rows = get_incidents()

    return jsonify(
        {
            "count": len(incident_rows),
            "incidents": incident_rows,
        }
    )


@app.get("/api/reports/summary")
def reports_summary():
    summary = get_report_summary()
    return jsonify(summary)


@app.get("/api/reports/csv")
def reports_csv():
    csv_content = generate_csv_report()
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"netshield_report_{now_str}.csv"
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "text/csv; charset=utf-8",
        },
    )


@app.get("/api/reports/pdf")
def reports_pdf():
    pdf_bytes = generate_pdf_report()
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"netshield_report_{now_str}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
        },
    )


# -------------------------------------------------------------------------
# PCAP Analysis Endpoints
# -------------------------------------------------------------------------

UPLOAD_FOLDER = Path(__file__).resolve().parent / "data" / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
SAMPLE_PCAP_DIR = Path(__file__).resolve().parent / "data" / "sample_pcaps"
SAMPLE_PCAP_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/api/pcap/samples")
def pcap_samples():
    """List sample PCAP captures bundled with the system."""
    samples = []
    if SAMPLE_PCAP_DIR.exists():
        for p in sorted(SAMPLE_PCAP_DIR.iterdir()):
            if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
                samples.append({
                    "filename": p.name,
                    "file_size_bytes": p.stat().st_size,
                    "path": str(p),
                })
    return jsonify({"count": len(samples), "samples": samples})


@app.post("/api/pcap/analyze")
def pcap_analyze():
    """Upload or select a PCAP file and run offline 31-feature ML analysis."""
    target_path = None
    original_filename = None

    if "file" in request.files:
        uploaded_file = request.files["file"]
        if uploaded_file and uploaded_file.filename:
            original_filename = Path(uploaded_file.filename).name
            timestamp = int(datetime.now().timestamp())
            saved_name = f"{timestamp}_{original_filename}"
            dest = UPLOAD_FOLDER / saved_name
            uploaded_file.save(dest)
            target_path = str(dest)
    else:
        data = request.get_json(silent=True) or {}
        if data.get("sample"):
            sample_file = SAMPLE_PCAP_DIR / data["sample"]
            if sample_file.exists():
                target_path = str(sample_file)
                original_filename = sample_file.name
        elif data.get("file_path"):
            fp = Path(data["file_path"])
            if fp.exists():
                target_path = str(fp)
                original_filename = fp.name

    if not target_path:
        return jsonify({"error": "No PCAP file uploaded or valid file path provided"}), 400

    try:
        report = analyze_pcap_file(target_path)
        if original_filename:
            report["filename"] = original_filename
        analysis_id = save_pcap_analysis(report)
        report["id"] = analysis_id
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": f"PCAP analysis failed: {str(exc)}"}), 500


@app.get("/api/pcap/analyses")
def pcap_analyses():
    """List past PCAP analyses stored in the database."""
    analyses = get_pcap_analyses()
    return jsonify({"count": len(analyses), "analyses": analyses})


@app.get("/api/pcap/results/<int:analysis_id>")
def pcap_result_detail(analysis_id: int):
    """Get full PCAP analysis results including time-window breakdowns."""
    analysis = get_pcap_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"error": "PCAP analysis record not found"}), 404
    return jsonify(analysis)


@app.get("/api/pcap/download/<int:analysis_id>/csv")
def pcap_download_csv(analysis_id: int):
    """Download time-window analysis results as CSV."""
    analysis = get_pcap_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"error": "PCAP analysis record not found"}), 404

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Window Index",
        "Window Start (s)",
        "Window End (s)",
        "Packet Count",
        "Prediction",
        "Label",
        "Attack Probability",
        "Normal Probability",
        "Attack Category",
        "Top Contributing Feature",
    ])
    for w in analysis.get("window_results", []):
        writer.writerow([
            w.get("window_index", 0),
            w.get("window_start", 0),
            w.get("window_end", 0),
            w.get("packet_count", 0),
            w.get("prediction", 0),
            w.get("label", "Normal"),
            round(w.get("attack_probability", 0), 4),
            round(w.get("normal_probability", 0), 4),
            w.get("attack_category", "Normal"),
            w.get("top_contributing_feature", "None"),
        ])

    csv_content = output.getvalue()
    stem = Path(analysis.get("filename", "analysis")).stem
    filename = f"pcap_analysis_{analysis_id}_{stem}.csv"
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "text/csv; charset=utf-8",
        },
    )


# -------------------------------------------------------------------------
# ML Testing & Model Evaluation Endpoints
# -------------------------------------------------------------------------

@app.get("/api/ml/test/schema")
def ml_test_schema():
    """Return model specifications and the 31 canonical feature definitions."""
    return jsonify({
        "status": "valid",
        "feature_count": V3_FEATURE_COUNT,
        "features": V3_FEATURE_NAMES,
        "model_name": "random_forest_awid3_v3_expanded.joblib",
        "target_column": "Label",
        "classification_type": "Binary (0=Normal, 1=Attack)",
        "feature_order_strict": True,
    })


@app.get("/api/ml/test/datasets")
def ml_test_datasets():
    """List available evaluation CSV datasets in backend/data/."""
    datasets = list_available_test_datasets()
    return jsonify({"count": len(datasets), "datasets": datasets})


@app.post("/api/ml/test/run")
def ml_test_run():
    """Run full evaluation on a test CSV dataset with 31-feature schema validation."""
    data = request.get_json(silent=True) or {}
    dataset_path = data.get("dataset_path")

    if not dataset_path and data.get("dataset_name"):
        candidate = Path(__file__).resolve().parent / "data" / data["dataset_name"]
        if candidate.exists():
            dataset_path = str(candidate)

    if not dataset_path:
        return jsonify({"error": "dataset_path or dataset_name required"}), 400

    try:
        report = evaluate_test_dataset(dataset_path)
        run_id = save_ml_test_run(report)
        report["id"] = run_id
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": f"Evaluation failed: {str(exc)}"}), 500


@app.get("/api/ml/test/runs")
def ml_test_runs():
    """List historical ML evaluation runs."""
    runs = get_ml_test_runs()
    return jsonify({"count": len(runs), "runs": runs})


@app.get("/api/ml/test/results/<int:run_id>")
def ml_test_result_detail(run_id: int):
    """Get full evaluation report by run ID."""
    run = get_ml_test_run_by_id(run_id)
    if not run:
        return jsonify({"error": "ML test run record not found"}), 404
    return jsonify(run)


# -------------------------------------------------------------------------
# Wi-Fi Network Recommendation & ML Scan Classification Endpoints
# -------------------------------------------------------------------------

@app.get("/api/wifi/recommendations")
def wifi_recommendations():
    """Classify current scanned networks using the dedicated recommendation ML model."""
    networks = read_networks()
    results = classify_and_recommend_networks(networks)
    return jsonify(results)


@app.post("/api/wifi/recommendations/analyze")
def wifi_recommendations_analyze():
    """Run ML recommendation inference on provided networks or current scan snapshot."""
    data = request.get_json(silent=True) or {}
    networks = data.get("networks")
    if networks is None:
        networks = read_networks()
    results = classify_and_recommend_networks(networks)
    return jsonify(results)


@app.get("/api/wifi/recommendations/model")
def wifi_recommendations_model():
    """Return model specification, performance metrics, and feature importances."""
    metadata = get_recommendation_model_metadata()
    return jsonify(metadata)


@app.post("/api/wifi/connect")
def wifi_connect():
    """Attempt connecting to a specified Wi-Fi network using the OS network manager."""
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid")
    password = data.get("password")
    result = attempt_wifi_connection(ssid, password)
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
    )
