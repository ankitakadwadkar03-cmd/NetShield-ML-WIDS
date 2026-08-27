from flask import Flask, jsonify
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


app = Flask(__name__)
CORS(app)


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
    from flask import request

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
    from flask import request

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
    from flask import request

    data = request.get_json(silent=True) or {}

    response, status_code = start_capture(
        data.get("interface")
    )

    return jsonify(response), status_code


@app.post("/api/capture/stop")
def capture_stop():
    response, status_code = stop_capture()

    return jsonify(response), status_code


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
    )
