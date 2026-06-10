#!/usr/bin/env python3
"""
PredatorEye — System Attack Path Predictor
Scans the local system, predicts attacker paths, and generates a remediation report.

Usage:
    python main.py                  # full scan, HTML + JSON reports
    python main.py --quick          # skip slow scans (software registry)
    python main.py --output dir/    # custom output directory
    python main.py --no-html        # JSON only
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
    parser.add_argument("--quick", action="store_true", help="Skip slow scans (software registry)")
    parser.add_argument("--output", default="output", help="Output directory (default: output/)")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    parser.add_argument("--no-json", action="store_true", help="Skip JSON report generation")
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

    start = time.time()

    if RICH:
        Console().print("\n[dim]Starting system scan...[/dim]\n")
    else:
        print("\n[*] Starting system scan...\n")

    scan_results = run_scan(args)
    findings, attack_paths, prediction, recommendations = analyse(scan_results)
    print_summary(prediction)

    # Generate reports
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = scan_results.get("system", {}).get("os_info", {}).get("hostname", "host")
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    outputs = []

    if not args.no_html:
        html_path = os.path.join(out_dir, f"predatoreye_{hostname}_{timestamp}.html")
        HTMLReporter(prediction, findings, recommendations, scan_results).write(html_path)
        outputs.append(("HTML Report", html_path))

    if not args.no_json:
        json_path = os.path.join(out_dir, f"predatoreye_{hostname}_{timestamp}.json")
        JSONReporter(prediction, findings, recommendations, scan_results).write(json_path)
        outputs.append(("JSON Report", json_path))

    elapsed = round(time.time() - start, 1)

    if RICH:
        console = Console()
        console.print(f"[dim]Scan completed in {elapsed}s[/dim]\n")
        for label, path in outputs:
            console.print(f"[green][+][/green] {label}: [underline]{path}[/underline]")
        console.print()
        if prediction["critical_count"] > 0:
            console.print(f"[red bold][!] {prediction['critical_count']} CRITICAL finding(s) require immediate action.[/red bold]")
    else:
        print(f"\n[*] Scan completed in {elapsed}s")
        for label, path in outputs:
            print(f"  [+] {label}: {path}")
        if prediction["critical_count"] > 0:
            print(f"\n  [!] {prediction['critical_count']} CRITICAL finding(s) require immediate action.")

    print()


if __name__ == "__main__":
    main()
