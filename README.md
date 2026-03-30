Sniffer Project Bundle
----------------------
Files:
  - sniffer_detector.py   : detection engine (Scapy-based)
  - snifferapi.py         : Flask API (receives PCAP and returns alerts)
  - index.html            : Web UI (upload PCAP, view alerts)
  - capture.pcap          : example pcap (optional)
  - alerts.csv            : sample alerts log (optional)
  - README.md             : this file
How to run:
  1) Install dependencies: pip install -r requirements.txt
  2) Start API: python snifferapi.py
  3) Open index.html in a browser (or use Live Server) and choose API URL -> Local.
Notes:
  - CORS is enabled in API. API runs on http://127.0.0.1:5000 by default.
  - Do not expose the API to the public without reviewing security implications.
