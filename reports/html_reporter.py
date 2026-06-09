"""
Generates a standalone, self-contained HTML report with interactive charts.
"""

import os
import json
import datetime


SEVERITY_BADGE = {
    "Critical": '<span class="badge critical">Critical</span>',
    "High":     '<span class="badge high">High</span>',
    "Medium":   '<span class="badge medium">Medium</span>',
    "Low":      '<span class="badge low">Low</span>',
    "Info":     '<span class="badge info">Info</span>',
}

SEVERITY_COLOR = {
    "Critical": "#c0392b",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#2ecc71",
    "Info":     "#3498db",
    "Minimal":  "#27ae60",
}


class HTMLReporter:
    def __init__(self, prediction: dict, findings: list, recommendations: dict, scan_results: dict):
        self.prediction = prediction
        self.findings = findings
        self.recommendations = recommendations
        self.scan_results = scan_results

    def write(self, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        html = self._build_html()
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return output_path

    # ------------------------------------------------------------------
    def _build_html(self) -> str:
        p = self.prediction
        sys_info = self.scan_results.get("system", {}).get("os_info", {})
        generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        risk_color = SEVERITY_COLOR.get(p.get("risk_level", ""), "#888")

        chart_data = json.dumps({
            "Critical": p.get("critical_count", 0),
            "High":     p.get("high_count", 0),
            "Medium":   p.get("medium_count", 0),
            "Low":      p.get("low_count", 0),
        })

        category_data = json.dumps(p.get("stats", {}).get("findings_by_category", {}))

        findings_html = self._findings_section()
        attack_paths_html = self._attack_paths_section()
        recommendations_html = self._recommendations_section()
        top_attacker = p.get("most_likely_attacker", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AttackPath Report — {sys_info.get('hostname', 'Unknown Host')}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
    --accent: #58a6ff; --danger: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}
  h1 {{ font-size: 2rem; font-weight: 700; }}
  h2 {{ font-size: 1.3rem; font-weight: 600; margin-bottom: 1rem; color: var(--accent); }}
  h3 {{ font-size: 1rem; font-weight: 600; margin-bottom: .5rem; }}

  .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 1px solid var(--border); padding: 2rem; }}
  .header-inner {{ max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
  .logo {{ font-size: 1.5rem; font-weight: 800; color: var(--accent); letter-spacing: -0.5px; }}
  .logo span {{ color: var(--danger); }}
  .meta {{ color: var(--muted); font-size: .85rem; }}

  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }}

  .risk-banner {{ background: var(--surface); border: 2px solid {risk_color}; border-radius: 12px; padding: 2rem; margin-bottom: 2rem; display: flex; align-items: center; gap: 2rem; flex-wrap: wrap; }}
  .risk-score-circle {{ width: 120px; height: 120px; border-radius: 50%; border: 6px solid {risk_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }}
  .risk-score-num {{ font-size: 2.2rem; font-weight: 800; color: {risk_color}; line-height: 1; }}
  .risk-score-label {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .risk-info {{ flex: 1; }}
  .risk-level-tag {{ display: inline-block; background: {risk_color}22; color: {risk_color}; border: 1px solid {risk_color}; border-radius: 6px; padding: .2rem .8rem; font-weight: 700; font-size: 1.1rem; margin-bottom: .5rem; }}

  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 800; }}
  .stat-label {{ font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }}
  .c {{ color: #f85149; }} .h {{ color: #e67e22; }} .m {{ color: #f1c40f; }} .l {{ color: #2ecc71; }}

  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
  @media (max-width: 768px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}

  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; }}

  .badge {{ padding: .15rem .6rem; border-radius: 4px; font-size: .75rem; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }}
  .badge.critical {{ background: #f8514922; color: #f85149; border: 1px solid #f85149; }}
  .badge.high     {{ background: #e67e2222; color: #e67e22; border: 1px solid #e67e22; }}
  .badge.medium   {{ background: #f1c40f22; color: #f1c40f; border: 1px solid #f1c40f; }}
  .badge.low      {{ background: #2ecc7122; color: #2ecc71; border: 1px solid #2ecc71; }}
  .badge.info     {{ background: #3498db22; color: #3498db; border: 1px solid #3498db; }}

  .finding-list {{ display: flex; flex-direction: column; gap: .75rem; }}
  .finding-item {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; border-left: 4px solid var(--border); }}
  .finding-item.Critical {{ border-left-color: #f85149; }}
  .finding-item.High     {{ border-left-color: #e67e22; }}
  .finding-item.Medium   {{ border-left-color: #f1c40f; }}
  .finding-item.Low      {{ border-left-color: #2ecc71; }}
  .finding-header {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .4rem; }}
  .finding-id {{ font-size: .75rem; color: var(--muted); font-family: monospace; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-desc {{ color: var(--muted); font-size: .875rem; }}
  .finding-category {{ font-size: .75rem; color: var(--accent); margin-top: .3rem; }}
  details summary {{ cursor: pointer; color: var(--accent); font-size: .85rem; margin-top: .5rem; }}
  details pre {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: .75rem; font-size: .8rem; overflow-x: auto; margin-top: .5rem; color: var(--text); }}

  .attack-path-item {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; }}
  .ap-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: .75rem; flex-wrap: wrap; gap: .5rem; }}
  .ap-title {{ font-weight: 700; font-size: 1rem; }}
  .ap-score {{ font-weight: 800; font-size: 1.1rem; }}
  .ap-desc {{ color: var(--muted); font-size: .875rem; margin-bottom: .75rem; }}
  .ap-steps {{ display: flex; flex-direction: column; gap: .5rem; }}
  .ap-step {{ display: flex; align-items: flex-start; gap: .5rem; font-size: .85rem; color: var(--muted); }}
  .step-num {{ background: var(--accent); color: #000; border-radius: 50%; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; font-size: .7rem; font-weight: 700; flex-shrink: 0; margin-top: .1rem; }}
  .likelihood-bar {{ height: 6px; background: var(--border); border-radius: 3px; margin-top: .75rem; overflow: hidden; }}
  .likelihood-fill {{ height: 100%; border-radius: 3px; }}

  .rec-item {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: .75rem; border-left: 4px solid var(--accent); }}
  .rec-header {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .75rem; }}
  .rec-steps {{ list-style: none; }}
  .rec-steps li {{ padding: .3rem 0 .3rem 1.5rem; position: relative; color: var(--muted); font-size: .875rem; }}
  .rec-steps li::before {{ content: '▸'; position: absolute; left: 0; color: var(--accent); }}
  .rec-steps code {{ background: var(--bg); border: 1px solid var(--border); border-radius: 3px; padding: .1rem .4rem; font-size: .8rem; color: #79c0ff; font-family: monospace; }}
  .rec-ref {{ font-size: .75rem; color: var(--muted); margin-top: .5rem; padding-top: .5rem; border-top: 1px solid var(--border); }}

  .attacker-box {{ background: var(--surface2); border: 1px solid #f8514944; border-radius: 10px; padding: 1.25rem; }}
  .attacker-label {{ font-size: .75rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }}
  .attacker-value {{ font-weight: 700; margin-bottom: .5rem; }}
  .tech-chip {{ display: inline-block; background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; border-radius: 4px; padding: .15rem .6rem; font-size: .75rem; margin: .2rem .2rem 0 0; }}

  .sys-table {{ width: 100%; border-collapse: collapse; font-size: .875rem; }}
  .sys-table td {{ padding: .4rem .75rem; border-bottom: 1px solid var(--border); }}
  .sys-table td:first-child {{ color: var(--muted); width: 40%; }}

  canvas {{ width: 100% !important; max-height: 260px; }}

  .section-title {{ font-size: 1.4rem; font-weight: 700; margin: 2rem 0 1rem; color: var(--text); display: flex; align-items: center; gap: .5rem; }}
  .section-title::before {{ content: ''; display: inline-block; width: 4px; height: 1.4rem; background: var(--accent); border-radius: 2px; }}

  footer {{ border-top: 1px solid var(--border); padding: 1.5rem; text-align: center; color: var(--muted); font-size: .8rem; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="header">
  <div class="header-inner">
    <div>
      <div class="logo">Attack<span>Path</span></div>
      <div class="meta">System Attack Path Predictor — Security Assessment Report</div>
    </div>
    <div style="text-align:right">
      <div style="font-weight:600">{sys_info.get('hostname', 'Unknown Host')}</div>
      <div class="meta">{sys_info.get('os', '')} {sys_info.get('release', '')} &bull; Scanned: {generated}</div>
    </div>
  </div>
</div>

<div class="container">

  <!-- Risk Banner -->
  <div class="risk-banner">
    <div class="risk-score-circle">
      <div class="risk-score-num">{p.get('overall_score', 0)}</div>
      <div class="risk-score-label">/ 100</div>
    </div>
    <div class="risk-info">
      <div class="risk-level-tag">{p.get('risk_level', 'Unknown')} Risk</div>
      <h1>Security Assessment Complete</h1>
      <p style="color:var(--muted);margin-top:.5rem">
        Found <strong>{p.get('total_findings', 0)} security findings</strong> across {p.get('total_attack_paths', 0)} predicted attack paths.
        {p.get('critical_count', 0)} critical issues require immediate attention.
      </p>
    </div>
  </div>

  <!-- Stats -->
  <div class="stat-grid">
    <div class="stat-card"><div class="stat-num c">{p.get('critical_count', 0)}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-num h">{p.get('high_count', 0)}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-num m">{p.get('medium_count', 0)}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card"><div class="stat-num l">{p.get('low_count', 0)}</div><div class="stat-label">Low</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--accent)">{p.get('total_attack_paths', 0)}</div><div class="stat-label">Attack Paths</div></div>
    <div class="stat-card"><div class="stat-num" style="color:var(--muted)">{p.get('total_findings', 0)}</div><div class="stat-label">Total Findings</div></div>
  </div>

  <!-- Charts + System Info -->
  <div class="grid-2">
    <div class="card">
      <h2>Findings by Severity</h2>
      <canvas id="severityChart"></canvas>
    </div>
    <div class="card">
      <h2>Findings by MITRE ATT&amp;CK Tactic</h2>
      <canvas id="categoryChart"></canvas>
    </div>
  </div>

  <!-- Attacker Profile + System Info -->
  <div class="grid-2">
    <div class="card">
      <h2>Most Likely Threat Actor</h2>
      <div class="attacker-box">
        <div class="attacker-label">Profile</div>
        <div class="attacker-value">{top_attacker.get('profile', 'Unknown')}</div>
        <div class="attacker-label">Motivation</div>
        <div class="attacker-value" style="color:var(--danger)">{top_attacker.get('motivation', 'Unknown')}</div>
        <div class="attacker-label" style="margin-top:.5rem">Likely Techniques</div>
        <div style="margin-top:.3rem">
          {''.join(f'<span class="tech-chip">{t}</span>' for t in top_attacker.get('techniques', []))}
        </div>
      </div>
    </div>
    <div class="card">
      <h2>System Information</h2>
      <table class="sys-table">
        <tr><td>Hostname</td><td>{sys_info.get('hostname', 'N/A')}</td></tr>
        <tr><td>OS</td><td>{sys_info.get('os', 'N/A')} {sys_info.get('release', '')}</td></tr>
        <tr><td>Current User</td><td>{sys_info.get('current_user', 'N/A')}</td></tr>
        <tr><td>Scan Time</td><td>{sys_info.get('scan_time', 'N/A')}</td></tr>
        <tr><td>Architecture</td><td>{sys_info.get('machine', 'N/A')}</td></tr>
      </table>
    </div>
  </div>

  <!-- Attack Paths -->
  <div class="section-title">Predicted Attack Paths</div>
  {attack_paths_html}

  <!-- Findings -->
  <div class="section-title">Security Findings</div>
  <div class="finding-list">
  {findings_html}
  </div>

  <!-- Recommendations -->
  <div class="section-title">Prevention & Remediation</div>
  <h3 style="color:var(--muted);margin-bottom:1rem">Specific Recommendations</h3>
  {recommendations_html}

  <h3 style="color:var(--muted);margin:1.5rem 0 1rem">General Security Hardening</h3>
  {''.join(self._general_rec_html(r) for r in self.recommendations.get('general', []))}

</div>

<footer>
  AttackPath v1.0.0 &bull; Generated {generated} &bull; For authorised use only &bull;
  <a href="https://github.com/yourusername/AttackPath">github.com/yourusername/AttackPath</a>
</footer>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
const chartData = {chart_data};
const categoryData = {category_data};
const COLORS = {{
  Critical: '#f85149', High: '#e67e22', Medium: '#f1c40f', Low: '#2ecc71', Info: '#3498db'
}};
const catColors = ['#58a6ff','#f85149','#e67e22','#f1c40f','#2ecc71','#bc8cff','#ff7b72','#79c0ff','#ffa657','#3fb950','#d2a8ff'];

new Chart(document.getElementById('severityChart'), {{
  type: 'doughnut',
  data: {{
    labels: Object.keys(chartData),
    datasets: [{{ data: Object.values(chartData), backgroundColor: Object.keys(chartData).map(k => COLORS[k]), borderWidth: 2, borderColor: '#161b22' }}]
  }},
  options: {{ plugins: {{ legend: {{ labels: {{ color: '#c9d1d9' }} }} }}, cutout: '65%' }}
}});

const cats = Object.keys(categoryData);
new Chart(document.getElementById('categoryChart'), {{
  type: 'bar',
  data: {{
    labels: cats,
    datasets: [{{ data: cats.map(c => categoryData[c]), backgroundColor: cats.map((_, i) => catColors[i % catColors.length]), borderRadius: 4 }}]
  }},
  options: {{
    indexAxis: 'y',
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#30363d' }} }},
      y: {{ ticks: {{ color: '#c9d1d9' }}, grid: {{ display: false }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    def _findings_section(self) -> str:
        if not self.findings:
            return '<div class="card" style="text-align:center;color:var(--muted);padding:3rem">No findings detected.</div>'
        parts = []
        for f in self.findings:
            badge = SEVERITY_BADGE.get(f.severity, f.severity)
            details_json = json.dumps(f.details, indent=2, default=str)
            parts.append(f"""
    <div class="finding-item {f.severity}">
      <div class="finding-header">
        <span class="finding-id">{f.id}</span>
        {badge}
        <span class="finding-title">{self._esc(f.title)}</span>
      </div>
      <div class="finding-desc">{self._esc(f.description)}</div>
      <div class="finding-category">MITRE ATT&amp;CK Tactic: {f.category}</div>
      {"" if not f.details else f'<details><summary>Technical details</summary><pre>{self._esc(details_json)}</pre></details>'}
    </div>""")
        return "\n".join(parts)

    def _attack_paths_section(self) -> str:
        paths = self.prediction.get("top_attack_paths", [])
        if not paths:
            return '<div class="card" style="text-align:center;color:var(--muted);padding:2rem">No significant attack paths identified.</div>'
        parts = []
        for i, ap in enumerate(paths):
            sev = ap.get("impact", "Medium")
            color = SEVERITY_COLOR.get(sev, "#888")
            likelihood = ap.get("likelihood", 0)
            likelihood_pct = int(likelihood * 100)
            risk_score = ap.get("risk_score", 0)
            steps_html = "".join(
                f'<div class="ap-step"><div class="step-num">{j+1}</div><div>{self._esc(s.get("title","") if isinstance(s,dict) else str(s))}</div></div>'
                for j, s in enumerate(ap.get("steps", []))
            )
            parts.append(f"""
    <div class="attack-path-item">
      <div class="ap-header">
        <div>
          <span style="font-size:.8rem;color:var(--muted);margin-right:.5rem">#{i+1}</span>
          <span class="ap-title">{self._esc(ap.get('name',''))}</span>
        </div>
        <div style="display:flex;align-items:center;gap:.75rem">
          {SEVERITY_BADGE.get(sev, sev)}
          <span class="ap-score" style="color:{color}">Risk: {risk_score}</span>
        </div>
      </div>
      <div class="ap-desc">{self._esc(ap.get('description',''))}</div>
      <div style="font-size:.8rem;color:var(--muted);margin-bottom:.5rem">Attack Steps ({len(ap.get('steps', []))} findings chain)</div>
      <div class="ap-steps">{steps_html}</div>
      <div class="likelihood-bar"><div class="likelihood-fill" style="width:{likelihood_pct}%;background:{color}"></div></div>
      <div style="font-size:.75rem;color:var(--muted);margin-top:.3rem">Likelihood: {likelihood_pct}%</div>
    </div>""")
        return "\n".join(parts)

    def _recommendations_section(self) -> str:
        recs = self.recommendations.get("specific", [])
        if not recs:
            return '<div style="color:var(--muted)">No specific recommendations generated.</div>'
        return "".join(self._specific_rec_html(r) for r in recs)

    def _specific_rec_html(self, rec: dict) -> str:
        badge = SEVERITY_BADGE.get(rec.get("severity", ""), "")
        steps_html = "".join(
            f'<li>{self._format_step(s)}</li>'
            for s in rec.get("steps", [])
        )
        ref = f'<div class="rec-ref">Reference: {self._esc(rec["reference"])}</div>' if rec.get("reference") else ""
        return f"""
    <div class="rec-item">
      <div class="rec-header">
        {badge}
        <span style="font-weight:600">{self._esc(rec.get('finding_title',''))}</span>
        <span style="font-size:.8rem;color:var(--muted)">{rec.get('finding_id','')}</span>
      </div>
      <ul class="rec-steps">{steps_html}</ul>
      {ref}
    </div>"""

    def _general_rec_html(self, rec: dict) -> str:
        steps_html = "".join(
            f'<li>{self._format_step(s)}</li>'
            for s in rec.get("steps", [])
        )
        return f"""
    <div class="rec-item" style="border-left-color:#3fb950">
      <h3 style="margin-bottom:.75rem">{self._esc(rec.get('title',''))}</h3>
      <ul class="rec-steps">{steps_html}</ul>
    </div>"""

    def _format_step(self, text: str) -> str:
        import re
        escaped = self._esc(text)
        # Wrap backtick code spans
        escaped = re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped)
        return escaped

    @staticmethod
    def _esc(text: str) -> str:
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
