#!/usr/bin/env python3
"""
PredatorEye — System Attack Path Predictor
Scans the local system, predicts attacker paths, and generates a remediation report.

Usage:
    python main.py                  # full scan, HTML + JSON reports
    python main.py --quick          # skip slow scans (software registry)
    python main.py --output dir/    # custom output directory
    python main.py --no-html        # JSON only
    python main.py --protect        # also run protection stack + correlation
"""

import sys
import os
import argparse
import datetime
import time

# Ensure the project root is on PYTHONPATH regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
    RICH = True
except ImportError:
    RICH = False

from scanners import (
    SystemScanner, NetworkScanner, ProcessScanner,
    SoftwareScanner, ServiceScanner, SecurityScanner,
)
from analyzers import AttackPathAnalyzer, RiskScorer
from predictors import PathPredictor
from prevention import RecommendationEngine
from reports import HTMLReporter, JSONReporter
from config import TOOL_NAME, TOOL_VERSION, SEVERITY_COLORS


def parse_args():
    parser = argparse.ArgumentParser(
        description="AttackPath — System Attack Path Predictor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                   Full scan with HTML + JSON reports
  python main.py --quick           Skip software registry scan (faster)
  python main.py --output reports/ Custom output directory
  python main.py --no-html         JSON report only
        """
    )
    parser.add_argument("--quick",   action="store_true", help="Skip slow scans (software registry)")
    parser.add_argument("--output",  default="output",    help="Output directory (default: output/)")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report generation")
    parser.add_argument(
        "--protect", action="store_true",
        help="Run protection stack (hash, YARA, behaviour, persistence) and cross-correlate with VA findings",
    )
    return parser.parse_args()


def print_banner():
    if RICH:
        c = Console()
        c.print(Panel.fit(
            f"[bold cyan]{TOOL_NAME}[/bold cyan]\n"
            f"[dim]Version {TOOL_VERSION}  |  Defensive Security Tool[/dim]",
            border_style="cyan",
        ))
    else:
        print("=" * 60)
        print(f"  {TOOL_NAME}")
        print(f"  Version {TOOL_VERSION}  |  Defensive Security Tool")
        print("=" * 60)


def run_scan(args) -> dict:
    scanners = [
        ("System Info & Users",   SystemScanner,   "system"),
        ("Network Ports",          NetworkScanner,   "network"),
        ("Running Processes",      ProcessScanner,   "processes"),
        ("Windows Services",       ServiceScanner,   "services"),
        ("Security Settings",      SecurityScanner,  "security"),
    ]
    if not args.quick:
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
        ) as progress:
            task = progress.add_task("Scanning...", total=len(scanners))
            for name, cls, key in scanners:
                progress.update(task, description=f"[cyan]Scanning:[/cyan] {name}")
                try:
                    results[key] = cls().scan()
                except Exception as e:
                    results[key] = {"error": str(e)}
                progress.advance(task)
    else:
        for name, cls, key in scanners:
            print(f"  [*] Scanning: {name}...")
            try:
                results[key] = cls().scan()
            except Exception as e:
                results[key] = {"error": str(e)}

    return results


def run_protection(console=None) -> dict:
    """
    Run all three detection layers + persistence monitor and return aggregated results.

    Scan directories: Downloads, Desktop, %TEMP% — non-recursive for speed.
    Each engine degrades gracefully if its optional dependency is absent.
    """
    from protection import SignatureEngine, YaraEngine, BehaviorMonitor, PersistenceMonitor

    home      = os.path.expanduser("~")
    scan_dirs = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop")]
    if os.name == "nt":
        scan_dirs.append(os.path.expandvars(r"%TEMP%"))
    else:
        scan_dirs.append("/tmp")
    scan_dirs = [d for d in scan_dirs if os.path.isdir(d)]

    results: dict = {
        "signature":   {"threats": [], "scanned": 0, "errors": []},
        "yara":        {"matches": [], "detections": 0, "errors": []},
        "behavior":    {"findings": [], "suspicious": 0, "errors": []},
        "persistence": {"findings": [], "changes": {}, "is_baseline_run": False, "errors": []},
        "file_watcher": {"detections": []},
        "scan_dirs":   scan_dirs,
    }

    def _step(label):
        if RICH and console:
            console.print(f"  [dim cyan]→[/dim cyan] {label}...")
        else:
            print(f"    → {label}...")

    # Layer 1: hash signatures
    _step("Hash signature scan")
    try:
        sig = SignatureEngine()
        for d in scan_dirs:
            r = sig.scan_directory(d, recursive=False)
            results["signature"]["threats"].extend(r.get("threats", []))
            results["signature"]["scanned"] += r.get("scanned", 0)
            results["signature"]["errors"].extend(r.get("errors", []))
    except Exception as exc:
        results["signature"]["errors"].append(str(exc))

    # Layer 2: YARA pattern matching
    _step("YARA rule scan")
    try:
        yara_eng = YaraEngine()
        if yara_eng.available:
            for d in scan_dirs:
                r = yara_eng.scan_directory(d, recursive=False)
                results["yara"]["matches"].extend(r.get("matches", []))
                results["yara"]["detections"] += r.get("detections", 0)
                results["yara"]["errors"].extend(r.get("errors", []))
        else:
            results["yara"]["errors"].append(
                yara_eng._load_error or "yara-python unavailable"
            )
    except Exception as exc:
        results["yara"]["errors"].append(str(exc))

    # Layer 3: behavioural heuristics
    _step("Behavioural process scan")
    try:
        monitor = BehaviorMonitor()
        results["behavior"] = monitor.scan_processes()
    except Exception as exc:
        results["behavior"]["errors"].append(str(exc))

    # Persistence delta
    _step("Persistence delta check")
    try:
        pers = PersistenceMonitor()
        results["persistence"] = pers.scan()
    except Exception as exc:
        results["persistence"]["errors"] = [str(exc)]

    return results


def run_correlation(findings: list, protection_results: dict) -> dict:
    from correlation import ThreatCorrelator
    return ThreatCorrelator().correlate(findings, protection_results)


def print_protection_summary(protection: dict, corr: dict, console=None):
    sig_n   = len(protection.get("signature", {}).get("threats", []))
    yara_n  = protection.get("yara", {}).get("detections", 0)
    beh_n   = protection.get("behavior", {}).get("suspicious", 0)
    pers_base = protection.get("persistence", {}).get("is_baseline_run", False)
    pers_n  = protection.get("persistence", {}).get("total_changes", 0)
    corr_n  = corr.get("total_correlations", 0)

    if RICH and console:
        from rich.table import Table
        from rich import box as rbox
        console.print()
        console.rule("[bold]PROTECTION STACK RESULTS[/bold]")
        console.print()
        t = Table(box=rbox.ROUNDED, show_header=False, border_style="dim")
        t.add_column("", style="dim", width=30)
        t.add_column("", style="bold")
        t.add_row("Signature (hash) detections",  f"[{'red' if sig_n else 'green'}]{sig_n}[/]")
        t.add_row("YARA rule matches",             f"[{'red' if yara_n else 'green'}]{yara_n}[/]")
        t.add_row("Suspicious processes",          f"[{'orange3' if beh_n else 'green'}]{beh_n}[/]")
        if pers_base:
            t.add_row("Persistence baseline",      "[dim]Created (re-run to detect changes)[/dim]")
        else:
            t.add_row("Persistence changes",       f"[{'orange3' if pers_n else 'green'}]{pers_n}[/]")
        t.add_row("Correlated findings",           f"[{'red bold' if corr_n else 'green'}]{corr_n}[/]")
        console.print(t)
        if corr_n:
            console.print(f"\n[red bold][!] {corr.get('correlation_summary','')}[/red bold]")
        console.print()
    else:
        print("\n  --- PROTECTION STACK ---")
        print(f"  Signature detections : {sig_n}")
        print(f"  YARA matches         : {yara_n}")
        print(f"  Suspicious processes : {beh_n}")
        print(f"  Persistence changes  : {'baseline created' if pers_base else pers_n}")
        print(f"  Correlated findings  : {corr_n}")
        if corr_n:
            print(f"\n  [!] {corr.get('correlation_summary','')}")


def analyse(scan_results: dict):
    scorer = RiskScorer(scan_results)
    findings = scorer.score()

    analyzer = AttackPathAnalyzer(findings)
    attack_paths = analyzer.analyze()

    predictor = PathPredictor(findings, attack_paths)
    prediction = predictor.predict()

    rec_engine = RecommendationEngine(findings)
    recommendations = rec_engine.generate()

    return findings, attack_paths, prediction, recommendations


def print_summary(prediction: dict):
    if RICH:
        console = Console()
        risk_color = {
            "Critical": "red", "High": "orange3", "Medium": "yellow",
            "Low": "green", "Minimal": "bright_green",
        }.get(prediction.get("risk_level", ""), "white")

        console.print()
        console.rule("[bold]SCAN RESULTS SUMMARY[/bold]")
        console.print()

        table = Table(box=box.ROUNDED, show_header=False, border_style="dim")
        table.add_column("", style="dim", width=28)
        table.add_column("", style="bold")
        table.add_row("Overall Risk Score", f"[{risk_color}]{prediction['overall_score']}/100  ({prediction['risk_level']})[/{risk_color}]")
        table.add_row("Critical Findings",  f"[red]{prediction['critical_count']}[/red]")
        table.add_row("High Findings",      f"[orange3]{prediction['high_count']}[/orange3]")
        table.add_row("Medium Findings",    f"[yellow]{prediction['medium_count']}[/yellow]")
        table.add_row("Total Findings",     str(prediction["total_findings"]))
        table.add_row("Attack Paths Found", str(prediction["total_attack_paths"]))
        console.print(table)

        attacker = prediction.get("most_likely_attacker", {})
        console.print()
        console.print(f"[bold]Most Likely Threat Actor:[/bold] [red]{attacker.get('profile', 'N/A')}[/red]")
        console.print(f"[dim]Motivation:[/dim] {attacker.get('motivation', 'N/A')}")

        top_paths = prediction.get("top_attack_paths", [])
        if top_paths:
            console.print()
            console.print("[bold]Top Attack Paths:[/bold]")
            for i, ap in enumerate(top_paths[:3], 1):
                console.print(f"  [cyan]{i}.[/cyan] {ap['name']} — Risk: [red]{ap['risk_score']}[/red] | Likelihood: {int(ap['likelihood']*100)}%")
        console.print()
    else:
        print()
        print("=" * 60)
        print("  SCAN RESULTS SUMMARY")
        print("=" * 60)
        print(f"  Overall Risk Score : {prediction['overall_score']}/100  ({prediction['risk_level']})")
        print(f"  Critical Findings  : {prediction['critical_count']}")
        print(f"  High Findings      : {prediction['high_count']}")
        print(f"  Total Findings     : {prediction['total_findings']}")
        print(f"  Attack Paths Found : {prediction['total_attack_paths']}")
        print()


def main():
    args = parse_args()
    print_banner()

    start   = time.time()
    console = Console() if RICH else None

    if RICH:
        console.print("\n[dim]Starting system scan...[/dim]\n")
    else:
        print("\n[*] Starting system scan...\n")

    scan_results = run_scan(args)
    findings, attack_paths, prediction, recommendations = analyse(scan_results)
    print_summary(prediction)

    # ── Optional protection stack ──────────────────────────────────────────────
    protection_results: dict = {}
    corr_results:       dict = {"correlated_findings": [], "total_correlations": 0,
                                "correlation_summary": "", "rules_evaluated": 0}

    if args.protect:
        if RICH:
            console.print("\n[bold cyan]Running protection stack...[/bold cyan]")
        else:
            print("\n[*] Running protection stack...")

        protection_results = run_protection(console=console)
        corr_results       = run_correlation(findings, protection_results)
        print_protection_summary(protection_results, corr_results, console=console)

    # ── Generate reports ───────────────────────────────────────────────────────
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname  = scan_results.get("system", {}).get("os_info", {}).get("hostname", "host")
    out_dir   = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    outputs = []

    if not args.no_html:
        html_path = os.path.join(out_dir, f"predatoreye_{hostname}_{timestamp}.html")
        HTMLReporter(
            prediction, findings, recommendations, scan_results,
            protection_results=protection_results,
            corr_results=corr_results,
        ).write(html_path)
        outputs.append(("HTML Report", html_path))

    if not args.no_json:
        json_path = os.path.join(out_dir, f"predatoreye_{hostname}_{timestamp}.json")
        JSONReporter(
            prediction, findings, recommendations, scan_results,
            protection_results=protection_results,
            corr_results=corr_results,
        ).write(json_path)
        outputs.append(("JSON Report", json_path))

    elapsed = round(time.time() - start, 1)

    if RICH:
        console.print(f"[dim]Scan completed in {elapsed}s[/dim]\n")
        for label, path in outputs:
            console.print(f"[green][+][/green] {label}: [underline]{path}[/underline]")
        console.print()
        if prediction["critical_count"] > 0:
            console.print(f"[red bold][!] {prediction['critical_count']} CRITICAL finding(s) require immediate action.[/red bold]")
        if corr_results["total_correlations"] > 0:
            console.print(f"[red bold][!] {corr_results['total_correlations']} CORRELATED finding(s) confirm active exploitation.[/red bold]")
    else:
        print(f"\n[*] Scan completed in {elapsed}s")
        for label, path in outputs:
            print(f"  [+] {label}: {path}")
        if prediction["critical_count"] > 0:
            print(f"\n  [!] {prediction['critical_count']} CRITICAL finding(s) require immediate action.")
        if corr_results["total_correlations"] > 0:
            print(f"\n  [!] {corr_results['total_correlations']} CORRELATED finding(s) confirm active exploitation.")

    print()


if __name__ == "__main__":
    main()
