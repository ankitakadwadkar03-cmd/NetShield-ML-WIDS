from flask import Flask, jsonify
from flask_cors import CORS

from scanner.adapter_manager import read_adapter_status
from scanner.network_reader import read_networks


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


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
    )
