"""
PredatorEye — Flask Backend
Runs as a hosted web server OR as the backend for the desktop app.
Desktop mode: triggered by PREDATOREYE_MODE=desktop env var.
"""

import sys
import os
import uuid
import json
import datetime
import threading
import time

from flask import (
    Flask, render_template, request,
    jsonify, send_from_directory, abort, url_for,
)

# ── Path setup (works normally and when frozen by PyInstaller) ────────────────
if getattr(sys, "frozen", False):
    _BASE = sys._MEIPASS
else:
    _BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys.path.insert(0, _BASE)

from analyzers import RiskScorer, AttackPathAnalyzer
from predictors import PathPredictor
from prevention import RecommendationEngine
from reports   import HTMLReporter

# ── Mode ─────────────────────────────────────────────────────────────────────
DESKTOP_MODE = os.environ.get("PREDATOREYE_MODE") == "desktop"

# ── Flask app ─────────────────────────────────────────────────────────────────
_tmpl_dir = os.path.join(_BASE, "web", "templates")
app = Flask(__name__, template_folder=_tmpl_dir)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

_stats = {"total_scans": 0}

# ── Scan state (desktop local scan) ──────────────────────────────────────────
_scan_lock  = threading.Lock()
_scan_state = {
    "running":   False,
    "step":      "",
    "progress":  0,
    "done":      False,
    "report_id": None,
    "error":     None,
    "prediction": None,
}

# ── File threat scan state ────────────────────────────────────────────────────
_file_scan_lock  = threading.Lock()
_file_scan_state = {
    "running":  False,
    "scanned":  0,
    "total":    0,
    "current":  "",
    "done":     False,
    "error":    None,
    "results":  None,
}


# ── Background cleanup (server mode only) ────────────────────────────────────
def _cleanup_loop():
    while True:
        time.sleep(3600)
        if DESKTOP_MODE:
            return                      # desktop keeps its own reports
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        for fname in os.listdir(REPORTS_DIR):
            fpath = os.path.join(REPORTS_DIR, fname)
            try:
                if datetime.datetime.fromtimestamp(os.path.getmtime(fpath)) < cutoff:
                    os.remove(fpath)
            except Exception:
                pass

threading.Thread(target=_cleanup_loop, daemon=True).start()


# ── Local scan runner (desktop mode) ─────────────────────────────────────────
def _run_local_scan(quick: bool) -> None:
    global _scan_state

    with _scan_lock:
        _scan_state = {
            "running": True, "step": "Starting...",
            "progress": 0, "done": False,
            "report_id": None, "error": None, "prediction": None,
        }

    try:
        from scanners import (
            SystemScanner, NetworkScanner, ProcessScanner,
            SoftwareScanner, ServiceScanner, SecurityScanner,
        )

        steps = [
            ("System Info & Users",  SystemScanner,  "system"),
            ("Network & Open Ports", NetworkScanner,  "network"),
            ("Running Processes",    ProcessScanner,  "processes"),
            ("Windows Services",     ServiceScanner,  "services"),
            ("Security Settings",    SecurityScanner, "security"),
        ]
        if not quick:
            steps.insert(3, ("Installed Software", SoftwareScanner, "software"))

        results = {}
        total   = len(steps)

        for i, (name, cls, key) in enumerate(steps):
            _scan_state["step"]     = name
            _scan_state["progress"] = int((i / total) * 75)
            try:
                results[key] = cls().scan()
            except Exception as e:
                results[key] = {"error": str(e)}

        _scan_state["step"]     = "Analysing attack paths..."
        _scan_state["progress"] = 80

        findings     = RiskScorer(results).score()
        attack_paths = AttackPathAnalyzer(findings).analyze()
        prediction   = PathPredictor(findings, attack_paths).predict()
        recs         = RecommendationEngine(findings).generate()

        _scan_state["step"]     = "Generating report..."
        _scan_state["progress"] = 92

        report_id = str(uuid.uuid4()).replace("-", "")[:16]
        html_path = os.path.join(REPORTS_DIR, f"{report_id}.html")
        HTMLReporter(prediction, findings, recs, results).write(html_path)

        _stats["total_scans"] += 1

        _scan_state.update({
            "running":    False,
            "step":       "Complete",
            "progress":   100,
            "done":       True,
            "report_id":  report_id,
            "prediction": {
                "risk_level":     prediction.get("risk_level"),
                "overall_score":  prediction.get("overall_score"),
                "total_findings": prediction.get("total_findings"),
                "total_attack_paths": prediction.get("total_attack_paths"),
                "critical_count": prediction.get("critical_count"),
            },
        })

    except Exception as e:
        _scan_state.update({"running": False, "error": str(e), "done": False})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", stats=_stats, desktop_mode=DESKTOP_MODE)


@app.route("/scan")
def scan():
    import socket, platform
    sys_hint = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
    }
    return render_template("scan.html", desktop_mode=DESKTOP_MODE, sys_hint=sys_hint)


# ── Desktop: start a local scan ───────────────────────────────────────────────
@app.route("/api/scan/local", methods=["POST"])
def scan_local():
    if not DESKTOP_MODE:
        return jsonify({"error": "Only available in desktop mode."}), 403

    if _scan_state.get("running"):
        return jsonify({"error": "A scan is already running."}), 409

    data  = request.get_json(silent=True) or {}
    quick = bool(data.get("quick", False))

    threading.Thread(target=_run_local_scan, args=(quick,), daemon=True).start()
    return jsonify({"status": "started"})


# ── Desktop: poll scan progress ───────────────────────────────────────────────
@app.route("/api/scan/status")
def scan_status():
    return jsonify(_scan_state)


# ── Server: upload JSON for analysis ─────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    f = request.files["file"]
    if not f.filename.endswith(".json"):
        return jsonify({"error": "Only .json files are accepted."}), 400

    try:
        scan_results = json.loads(f.read(5 * 1024 * 1024))
    except Exception:
        return jsonify({"error": "Invalid JSON. Upload the file from the PredatorEye agent."}), 400

    if not isinstance(scan_results, dict):
        return jsonify({"error": "Unexpected JSON format."}), 400

    try:
        findings     = RiskScorer(scan_results).score()
        attack_paths = AttackPathAnalyzer(findings).analyze()
        prediction   = PathPredictor(findings, attack_paths).predict()
        recs         = RecommendationEngine(findings).generate()
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500

    report_id = str(uuid.uuid4()).replace("-", "")[:16]
    html_path = os.path.join(REPORTS_DIR, f"{report_id}.html")
    try:
        HTMLReporter(prediction, findings, recs, scan_results).write(html_path)
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500

    _stats["total_scans"] += 1

    return jsonify({
        "report_id":  report_id,
        "report_url": url_for("view_report", report_id=report_id, _external=True),
        "risk_level": prediction.get("risk_level"),
        "risk_score": prediction.get("overall_score"),
        "findings":   prediction.get("total_findings"),
    })


@app.route("/report/<report_id>")
def view_report(report_id):
    if not report_id.isalnum() or len(report_id) > 32:
        abort(404)
    html_path = os.path.join(REPORTS_DIR, f"{report_id}.html")
    if not os.path.exists(html_path):
        return render_template("expired.html"), 404
    return send_from_directory(REPORTS_DIR, f"{report_id}.html")


@app.route("/download/agent")
def download_agent():
    agent_src = os.path.join(_BASE, "agent.py")
    return send_from_directory(
        os.path.dirname(agent_src), "agent.py",
        as_attachment=True, download_name="predatoreye-agent.py",
    )


@app.route("/api/save-agent", methods=["POST"])
def save_agent():
    """Desktop mode: copy agent.py to the user's Downloads folder."""
    if not DESKTOP_MODE:
        return jsonify({"error": "Only available in desktop mode."}), 400
    import shutil
    agent_src = os.path.join(_BASE, "agent.py")
    if not os.path.exists(agent_src):
        return jsonify({"error": "agent.py not found in application bundle."}), 404
    downloads = os.path.expanduser("~/Downloads")
    os.makedirs(downloads, exist_ok=True)
    dest = os.path.join(downloads, "predatoreye-agent.py")
    shutil.copy2(agent_src, dest)
    return jsonify({"status": "saved", "path": dest})


# ── File Threat Scanner ───────────────────────────────────────────────────────

@app.route("/file-scan")
def file_scan_page():
    if not DESKTOP_MODE:
        abort(403)
    from scanners import SCAN_LOCATIONS
    locations = {k: v for k, v in SCAN_LOCATIONS.items() if v and os.path.isdir(v)}
    return render_template("file_scan.html", desktop_mode=DESKTOP_MODE, locations=locations)


def _run_file_scan(selected_paths: list) -> None:
    global _file_scan_state
    from scanners import FileThreatScanner

    with _file_scan_lock:
        _file_scan_state = {
            "running": True, "scanned": 0, "total": 0,
            "current": "Collecting files...", "done": False,
            "error": None, "results": None,
        }

    try:
        scanner = FileThreatScanner(locations=selected_paths)

        def _sync_progress():
            while _file_scan_state["running"]:
                with _file_scan_lock:
                    _file_scan_state["scanned"] = scanner.progress["scanned"]
                    _file_scan_state["total"]   = scanner.progress["total"]
                    _file_scan_state["current"] = scanner.progress["current"]
                time.sleep(0.4)

        watcher = threading.Thread(target=_sync_progress, daemon=True)
        watcher.start()

        results = scanner.scan()

        with _file_scan_lock:
            _file_scan_state.update({
                "running": False, "done": True,
                "results": results,
                "scanned": results["total_scanned"],
                "total":   results["total_scanned"],
                "current": "Complete",
            })

    except Exception as e:
        with _file_scan_lock:
            _file_scan_state.update({"running": False, "error": str(e), "done": False})


@app.route("/api/file-scan/start", methods=["POST"])
def file_scan_start():
    if not DESKTOP_MODE:
        return jsonify({"error": "Desktop mode only."}), 403

    if _file_scan_state.get("running"):
        return jsonify({"error": "Scan already running."}), 409

    from scanners import SCAN_LOCATIONS
    data     = request.get_json(silent=True) or {}
    chosen   = data.get("locations", list(SCAN_LOCATIONS.keys()))
    paths    = [SCAN_LOCATIONS[k] for k in chosen if k in SCAN_LOCATIONS and SCAN_LOCATIONS[k]]

    if not paths:
        return jsonify({"error": "No valid scan locations selected."}), 400

    threading.Thread(target=_run_file_scan, args=(paths,), daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/file-scan/status")
def file_scan_status():
    return jsonify(_file_scan_state)


# ── Dev server entry ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
