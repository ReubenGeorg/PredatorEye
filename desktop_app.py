#!/usr/bin/env python3
"""
PredatorEye Desktop App
Starts the Flask backend locally and opens a native window via pywebview.
The scan runs entirely on the user's machine — nothing is uploaded.

Run:   python desktop_app.py
Build: build.bat  (produces dist/PredatorEye.exe)
"""

import sys
import os
import socket
import threading
import time
import urllib.request

# ── Resolve project root (works both normally and when frozen by PyInstaller) ─
if getattr(sys, "frozen", False):
    ROOT = sys._MEIPASS          # PyInstaller temp-extract directory
else:
    ROOT = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "web"))

import webview


# ── Helpers ───────────────────────────────────────────────────────────────────

def _free_port() -> int:
    """Return an available localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _start_flask(port: int) -> None:
    """Run Flask in a daemon thread."""
    os.environ["PREDATOREYE_MODE"] = "desktop"
    os.environ["PREDATOREYE_PORT"] = str(port)

    # Point Flask at the correct template/static folders when frozen
    tmpl_dir   = os.path.join(ROOT, "web", "templates")
    static_dir = os.path.join(ROOT, "web", "static")

    from flask import Flask as _Flask
    import web.app as _web

    _web.app.template_folder = tmpl_dir
    if os.path.isdir(static_dir):
        _web.app.static_folder = static_dir

    _web.app.run(
        host="127.0.0.1",
        port=port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


def _wait_for_server(port: int, timeout: float = 15.0) -> bool:
    """Poll until Flask is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            return True
        except Exception:
            time.sleep(0.15)
    return False


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    port = _free_port()

    flask_thread = threading.Thread(target=_start_flask, args=(port,), daemon=True)
    flask_thread.start()

    ready = _wait_for_server(port)

    if not ready:
        _error_html = """
        <body style="background:#080c14;color:#e63946;font-family:sans-serif;
                     display:flex;flex-direction:column;align-items:center;
                     justify-content:center;height:100vh;text-align:center">
          <h2>PredatorEye failed to start</h2>
          <p style="color:#6e7fa3;margin-top:.5rem">
            Make sure all dependencies are installed:<br>
            <code style="color:#79c0ff">pip install flask psutil rich pywebview</code>
          </p>
        </body>"""
        webview.create_window("PredatorEye — Error", html=_error_html,
                              width=600, height=300)
        webview.start()
        return

    window = webview.create_window(
        title="PredatorEye — System Attack Path Predictor",
        url=f"http://127.0.0.1:{port}/",
        width=1300,
        height=840,
        min_size=(960, 640),
        background_color="#080c14",
        text_select=True,
        zoomable=True,
    )

    webview.start(debug=False, private_mode=False)


if __name__ == "__main__":
    main()
