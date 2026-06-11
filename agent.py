#!/usr/bin/env python3
"""
PredatorEye Agent — Standalone local scanner
Scans your device and saves results to scan_results.json.

Usage:
    python predatoreye-agent.py                          # scan only
    python predatoreye-agent.py --upload https://url     # scan + upload
    python predatoreye-agent.py --quick                  # faster (skip software)

Requirements: pip install psutil rich
"""

import sys
import os
import json
import time
import datetime
import argparse

# ── Dependency check ─────────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    print("[!] Missing dependency: run  pip install psutil rich  first.")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    RICH = True
except ImportError:
    RICH = False

# ── Add parent dir so scanners/ etc. are importable if running from the repo ─
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)


def parse_args():
    p = argparse.ArgumentParser(description="PredatorEye Agent — local system scanner")
    p.add_argument("--quick",  action="store_true", help="Skip software registry scan (faster)")
    p.add_argument("--upload", metavar="URL",        help="Upload results to this PredatorEye server URL")
    p.add_argument("--output", default=".",          help="Directory to save scan_results.json")
    return p.parse_args()


def banner():
    print()
    print("=" * 52)
    print("   PredatorEye Agent  —  Local System Scanner")
    print("   See What Attackers See")
    print("=" * 52)
    print()


def run_scan(quick: bool) -> dict:
    from scanners import (
        SystemScanner, NetworkScanner, ProcessScanner,
        SoftwareScanner, ServiceScanner, SecurityScanner,
    )

    scanners = [
        ("System Info & Users",  SystemScanner,  "system"),
        ("Network & Open Ports", NetworkScanner,  "network"),
        ("Running Processes",    ProcessScanner,  "processes"),
        ("Windows Services",     ServiceScanner,  "services"),
        ("Security Settings",    SecurityScanner, "security"),
    ]
    if not quick:
        scanners.insert(3, ("Installed Software", SoftwareScanner, "software"))

    results = {}

    if RICH:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("Scanning...", total=len(scanners))
            for name, cls, key in scanners:
                prog.update(task, description=f"[cyan]Scanning:[/cyan] {name}")
                try:
                    results[key] = cls().scan()
                except Exception as e:
                    results[key] = {"error": str(e)}
                prog.advance(task)
    else:
        for name, cls, key in scanners:
            print(f"  [*] {name}...")
            try:
                results[key] = cls().scan()
            except Exception as e:
                results[key] = {"error": str(e)}

    return results


def save_json(results: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "scan_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return out_path


def upload(json_path: str, server_url: str) -> str:
    """Upload scan_results.json to the PredatorEye server."""
    import urllib.request
    import urllib.error

    server_url = server_url.rstrip("/")
    api_url    = f"{server_url}/api/analyze"

    boundary = "----PredatorEyeBoundary"
    with open(json_path, "rb") as fh:
        file_data = fh.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="scan_results.json"\r\n'
        f"Content-Type: application/json\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        api_url,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            return data.get("report_url", "")
    except urllib.error.HTTPError as e:
        err = json.loads(e.read()).get("error", str(e))
        print(f"[!] Upload failed: {err}")
        return ""
    except Exception as e:
        print(f"[!] Upload error: {e}")
        return ""


def main():
    args = parse_args()
    banner()

    start = time.time()
    print("[*] Starting scan... (run as Administrator for full results)\n")

    results  = run_scan(args.quick)
    out_path = save_json(results, args.output)
    elapsed  = round(time.time() - start, 1)

    print(f"\n[+] Scan complete in {elapsed}s")
    print(f"[+] Results saved to: {out_path}")

    if args.upload:
        print(f"\n[*] Uploading to {args.upload} ...")
        report_url = upload(out_path, args.upload)
        if report_url:
            print(f"[+] Report ready: {report_url}")
        else:
            print("[!] Upload failed. You can manually upload scan_results.json at the website.")
    else:
        print()
        print("─" * 52)
        print("  Next step: upload scan_results.json at:")
        print("  https://your-predatoreye-server.com/scan")
        print("─" * 52)

    print()


if __name__ == "__main__":
    main()
