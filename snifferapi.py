# Simple REST API wrapper for the Packet Sniffer (Flask)
# ------------------------------------------------------
# This API allows you to:
#   • Upload a pcap file via POST
#   • Run the sniffer on the uploaded pcap
#   • Return the alerts as JSON
#   • No live sniffing exposed for safety
#
# Run:
#   pip install flask scapy rich
#   python api.py
#
# Upload using curl:
#   curl -X POST -F "file=@capture.pcap" http://127.0.0.1:5000/analyze
#
# Response:
#   { "alerts": [ {"time":..., "type":..., "src":..., "dst":..., "detail":...}, ... ] }

from flask import Flask, request, jsonify
import os
import tempfile
from sniffer_detector import Detector, build_argparser, sniff_pcap

from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Disable Flask verbose logging
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/')
def index():
    return {"status": "sniffer api running"}

@app.route('/analyze', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "no file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "empty filename"}), 400

    # Save uploaded pcap
    tmpdir = tempfile.mkdtemp()
    pcap_path = os.path.join(tmpdir, file.filename)
    file.save(pcap_path)

    # Prepare Detector with default parameters
    args = SimpleNamespace(
        pcap=pcap_path,
        iface=None,
        out=os.path.join(tmpdir, "alerts.csv"),
        window=10,
        syn_count=30,
        scan_unique_ports=40,
        dos_pps=200,
        dns_qps=50,
        dns_long_label=40,
        dns_label_count=6,
        dns_entropy=3.8,
    )

    detector = Detector(args)

    # Patch the detector.alert() to capture alerts into memory
    memory_alerts = []
    original_alert = detector.alert

    def capture_alert(atype, src, dst, detail):
        memory_alerts.append({
            "time": None,  # skip timestamp for simplicity
            "type": atype,
            "src": src,
            "dst": dst,
            "detail": detail
        })
        original_alert(atype, src, dst, detail)  # still logs to CSV

    detector.alert = capture_alert

    # Run analysis
    try:
        sniff_pcap(args, detector)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        detector.close()

    return jsonify({"alerts": memory_alerts})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

