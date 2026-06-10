"""
PredatorEye — HTML Report Generator
Self-contained interactive security dashboard with animated gauge,
MITRE ATT&CK radar, attack-path flow diagrams, and filterable findings.
"""

import os
import json
import datetime
import re

# ── Severity helpers ────────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "Critical": "#e63946",
    "High":     "#ff8c42",
    "Medium":   "#ffd166",
    "Low":      "#00e676",
    "Info":     "#00d4ff",
    "Minimal":  "#00d4ff",
}

def _badge(sev):
    return f'<span class="badge b{sev[0].lower()}">{sev}</span>'

# ── Module-level constants (plain strings — no f-string, braces are literal) ─

EYE_SVG = """<svg class="eye-icon" viewBox="0 0 64 40" xmlns="http://www.w3.org/2000/svg">
  <path d="M2 20 C12 2 52 2 62 20 C52 38 12 38 2 20Z"
        fill="none" stroke="#e63946" stroke-width="3"/>
  <circle cx="32" cy="20" r="9" fill="#e63946"/>
  <circle cx="32" cy="20" r="4" fill="#080c14"/>
  <circle cx="35" cy="17" r="2" fill="#ff6b7a" opacity="0.7"/>
</svg>"""

# ── CSS (plain string — braces are CSS, not Python) ──────────────────────────
_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080c14;color:#cdd6f4;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.6}
a{color:#00d4ff;text-decoration:none}
b,strong{font-weight:700}

/* ── Header ── */
header{background:linear-gradient(135deg,#0a0f1e,#0d1421);border-bottom:1px solid #1e2d45;padding:1.2rem 2rem}
.hi{max-width:1300px;margin:0 auto;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}
.brand{display:flex;align-items:center;gap:.9rem}
.eye-icon{width:48px;height:30px;flex-shrink:0}
.bname{font-size:1.6rem;font-weight:900;letter-spacing:-1px;color:#cdd6f4}
.bname span{color:#e63946}
.bsub{font-size:.78rem;color:#6e7fa3;letter-spacing:.5px;text-transform:uppercase}
.hmeta{text-align:right}
.hhost{font-weight:700;font-size:1rem}
.htime{color:#6e7fa3;font-size:.8rem}

/* ── Main ── */
main{max-width:1300px;margin:0 auto;padding:1.5rem 1rem 3rem}
section{margin-bottom:2rem}

/* ── Hero ── */
.hero{background:linear-gradient(135deg,#0d1421,#0f1929);border:1px solid #1e2d45;border-radius:14px;padding:2rem;display:flex;align-items:center;gap:2.5rem;flex-wrap:wrap}
.gw{position:relative;flex-shrink:0}
.gl{position:absolute;top:50%;left:50%;transform:translate(-50%,-30%);text-align:center;pointer-events:none}
.gscore{font-size:2.8rem;font-weight:900;line-height:1}
.g100{font-size:.8rem;color:#6e7fa3}
.glevel{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-top:.2rem}
.hinfo{flex:1;min-width:220px}
.hinfo h1{font-size:1.6rem;font-weight:800;margin-bottom:.4rem}
.hsub{color:#6e7fa3;margin-bottom:1.2rem}
.pills{display:flex;gap:.75rem;flex-wrap:wrap}
.pill{display:flex;flex-direction:column;align-items:center;padding:.6rem 1.1rem;border-radius:10px;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.5px;border:1px solid}
.pill b{font-size:1.6rem;font-weight:900;line-height:1;margin-bottom:.1rem}
.pc{color:#e63946;border-color:#e6394644;background:#e6394610}
.ph{color:#ff8c42;border-color:#ff8c4244;background:#ff8c4210}
.pm{color:#ffd166;border-color:#ffd16644;background:#ffd16610}
.pl{color:#00e676;border-color:#00e67644;background:#00e67610}

/* ── Charts ── */
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.2rem}
.cc{background:#0d1421;border:1px solid #1e2d45;border-radius:12px;padding:1.2rem}
.ctitle{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#6e7fa3;margin-bottom:1rem}

/* ── Info grid ── */
.ig{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
@media(max-width:700px){.ig{grid-template-columns:1fr}}
.card{background:#0d1421;border:1px solid #1e2d45;border-radius:12px;padding:1.2rem}
.ct{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#6e7fa3;margin-bottom:1rem}
.itbl{width:100%;border-collapse:collapse;font-size:.875rem}
.itbl td{padding:.45rem .5rem;border-bottom:1px solid #1e2d45}
.itbl td:first-child{color:#6e7fa3;width:42%}
.atk-card{border-color:#e6394630}
.aprof{font-size:1.1rem;font-weight:800;color:#e63946;margin-bottom:.4rem}
.amot{font-size:.875rem;margin-bottom:.8rem;color:#cdd6f4}
.amot span{color:#6e7fa3}
.chips{display:flex;flex-wrap:wrap;gap:.4rem}
.chip{background:#e6394615;color:#e63946;border:1px solid #e6394640;border-radius:5px;padding:.15rem .6rem;font-size:.75rem}

/* ── Section header ── */
.sh{font-size:1.2rem;font-weight:800;margin-bottom:1rem;color:#cdd6f4;display:flex;align-items:center;gap:.6rem}
.sh::before{content:'';display:inline-block;width:4px;height:1.2rem;background:#e63946;border-radius:2px}
.sub-sh{font-size:.9rem;font-weight:700;color:#6e7fa3;text-transform:uppercase;letter-spacing:.5px;margin-bottom:.75rem}

/* ── Attack paths ── */
.ap{background:#0d1421;border:1px solid #1e2d45;border-radius:12px;padding:1.2rem;margin-bottom:1rem}
.ap-hdr{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem;margin-bottom:.6rem}
.ap-title{font-weight:800;font-size:.95rem}
.ap-meta{display:flex;align-items:center;gap:.6rem}
.ap-risk{font-weight:900;font-size:1rem}
.ap-desc{color:#6e7fa3;font-size:.85rem;margin-bottom:.9rem}
.flow{display:flex;align-items:center;flex-wrap:wrap;gap:0;margin-bottom:.9rem}
.flow-step{background:#131c2e;border:1px solid #1e2d45;border-radius:8px;padding:.4rem .75rem;font-size:.78rem;max-width:180px;position:relative}
.flow-step .sn{font-size:.65rem;color:#6e7fa3;margin-bottom:.1rem}
.flow-step .st{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.flow-arrow{color:#1e2d45;font-size:1.2rem;padding:0 .3rem;flex-shrink:0}
.lbar{height:6px;background:#1e2d45;border-radius:3px;overflow:hidden;margin-top:.5rem}
.lbar-fill{height:100%;border-radius:3px;transition:width 1s ease}
.lbar-lbl{font-size:.75rem;color:#6e7fa3;margin-top:.3rem}

/* ── Findings ── */
.fbar{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem;align-items:center}
.fb{background:#131c2e;border:1px solid #1e2d45;color:#6e7fa3;border-radius:6px;padding:.3rem .8rem;font-size:.8rem;cursor:pointer;transition:.15s}
.fb:hover{border-color:#e63946;color:#cdd6f4}
.fb.active{background:#e6394620;border-color:#e63946;color:#e63946;font-weight:700}
.fi{background:#0d1421;border:1px solid #1e2d45;border-radius:10px;padding:.9rem 1rem;margin-bottom:.6rem;border-left:4px solid #1e2d45;transition:.15s}
.fi:hover{border-left-color:var(--sc)}
.fi[data-sev="Critical"]{--sc:#e63946}
.fi[data-sev="High"]{--sc:#ff8c42}
.fi[data-sev="Medium"]{--sc:#ffd166}
.fi[data-sev="Low"]{--sc:#00e676}
.fi-hdr{display:flex;align-items:center;gap:.6rem;margin-bottom:.3rem;flex-wrap:wrap}
.fid{font-size:.72rem;color:#6e7fa3;font-family:monospace}
.ftitle{font-weight:700;flex:1}
.fdesc{color:#6e7fa3;font-size:.85rem}
.fcat{font-size:.75rem;color:#00d4ff;margin-top:.3rem}
details summary{cursor:pointer;color:#00d4ff;font-size:.8rem;margin-top:.4rem;user-select:none}
details pre{background:#080c14;border:1px solid #1e2d45;border-radius:6px;padding:.6rem;font-size:.78rem;overflow-x:auto;margin-top:.4rem;color:#cdd6f4;white-space:pre-wrap}

/* ── Badges ── */
.badge{padding:.15rem .55rem;border-radius:4px;font-size:.72rem;font-weight:800;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.bc{background:#e6394615;color:#e63946;border:1px solid #e6394650}
.bh{background:#ff8c4215;color:#ff8c42;border:1px solid #ff8c4250}
.bm{background:#ffd16615;color:#ffd166;border:1px solid #ffd16650}
.bl{background:#00e67615;color:#00e676;border:1px solid #00e67650}
.bi{background:#00d4ff15;color:#00d4ff;border:1px solid #00d4ff50}

/* ── Recommendations ── */
.rec{background:#0d1421;border:1px solid #1e2d45;border-left:4px solid #00d4ff;border-radius:10px;padding:1rem;margin-bottom:.75rem}
.rec.rc{border-left-color:#e63946}
.rec.rh{border-left-color:#ff8c42}
.rec.rm{border-left-color:#ffd166}
.rec-hdr{display:flex;align-items:center;gap:.6rem;margin-bottom:.7rem;flex-wrap:wrap}
.rec-title{font-weight:700}
.rec-fid{font-size:.75rem;color:#6e7fa3;font-family:monospace}
.steps{list-style:none}
.steps li{padding:.3rem 0 .3rem 1.4rem;position:relative;color:#6e7fa3;font-size:.85rem}
.steps li::before{content:'▸';position:absolute;left:0;color:#00d4ff}
.steps code{background:#080c14;border:1px solid #1e2d45;border-radius:3px;padding:.1rem .35rem;font-size:.78rem;color:#79c0ff;font-family:'Courier New',monospace;cursor:pointer}
.steps code:hover{border-color:#00d4ff}
.rec-ref{font-size:.75rem;color:#6e7fa3;border-top:1px solid #1e2d45;margin-top:.5rem;padding-top:.5rem}

/* ── Footer ── */
footer{border-top:1px solid #1e2d45;padding:1.2rem;text-align:center;color:#6e7fa3;font-size:.8rem;margin-top:2rem}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#0d1421}
::-webkit-scrollbar-thumb{background:#1e2d45;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#2a3f5f}

@media(max-width:600px){
  .hero{flex-direction:column;align-items:flex-start}
  .charts{grid-template-columns:1fr}
  .flow{flex-direction:column;align-items:flex-start}
  .flow-arrow{transform:rotate(90deg)}
}
"""

# ── JavaScript (plain string) ────────────────────────────────────────────────
_JS_LOGIC = """
// ── Gauge ────────────────────────────────────────────────────────────────────
(function() {
  var canvas = document.getElementById('gauge');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var W = canvas.width, H = canvas.height;
  var cx = W / 2, cy = H * 0.88, r = W * 0.36;

  var col = SCORE < 25 ? '#00e676' : SCORE < 50 ? '#ffd166' : SCORE < 75 ? '#ff8c42' : '#e63946';

  // zone colours behind arc
  var zoneGrad = ctx.createLinearGradient(cx - r, 0, cx + r, 0);
  zoneGrad.addColorStop(0, '#00e67630');
  zoneGrad.addColorStop(0.4, '#ffd16630');
  zoneGrad.addColorStop(0.7, '#ff8c4230');
  zoneGrad.addColorStop(1, '#e6394630');

  function drawTicks() {
    for (var i = 0; i <= 10; i++) {
      var a = Math.PI + (i / 10) * Math.PI;
      var major = (i % 5 === 0);
      var r1 = major ? r - 14 : r - 8;
      var r2 = r + 5;
      ctx.beginPath();
      ctx.moveTo(cx + r1 * Math.cos(a), cy + r1 * Math.sin(a));
      ctx.lineTo(cx + r2 * Math.cos(a), cy + r2 * Math.sin(a));
      ctx.strokeStyle = major ? '#2a3f5f' : '#1e2d45';
      ctx.lineWidth = major ? 2 : 1;
      ctx.stroke();
    }
    // zone labels
    var lbls = [['0', 0], ['25', 0.25], ['50', 0.5], ['75', 0.75], ['100', 1]];
    ctx.fillStyle = '#6e7fa3';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    lbls.forEach(function(l) {
      var a = Math.PI + l[1] * Math.PI;
      var rx = cx + (r + 16) * Math.cos(a);
      var ry = cy + (r + 16) * Math.sin(a);
      ctx.fillText(l[0], rx, ry);
    });
  }

  function draw(prog) {
    ctx.clearRect(0, 0, W, H);

    // background zone arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 0, false);
    ctx.strokeStyle = zoneGrad;
    ctx.lineWidth = 20;
    ctx.lineCap = 'butt';
    ctx.stroke();

    // base arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 0, false);
    ctx.strokeStyle = '#131c2e';
    ctx.lineWidth = 16;
    ctx.lineCap = 'round';
    ctx.stroke();

    drawTicks();

    // score arc
    var endA = Math.PI + prog * Math.PI;
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, endA, false);
    ctx.strokeStyle = col;
    ctx.lineWidth = 16;
    ctx.lineCap = 'round';
    ctx.shadowColor = col;
    ctx.shadowBlur = 12;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // needle
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    var nx = cx + (r - 22) * Math.cos(endA);
    var ny = cy + (r - 22) * Math.sin(endA);
    ctx.lineTo(nx, ny);
    ctx.strokeStyle = '#fff';
    ctx.lineWidth = 2.5;
    ctx.lineCap = 'round';
    ctx.stroke();

    // hub
    ctx.beginPath();
    ctx.arc(cx, cy, 6, 0, Math.PI * 2);
    ctx.fillStyle = col;
    ctx.fill();
    ctx.beginPath();
    ctx.arc(cx, cy, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#080c14';
    ctx.fill();
  }

  // animate
  var cur = 0, target = SCORE / 100;
  function animate() {
    cur += (target - cur) * 0.06;
    draw(cur);
    if (Math.abs(target - cur) > 0.001) requestAnimationFrame(animate);
    else draw(target);
  }
  draw(0);
  animate();
})();

// ── Severity Doughnut ────────────────────────────────────────────────────────
new Chart(document.getElementById('sevChart'), {
  type: 'doughnut',
  data: {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: SEV,
      backgroundColor: ['#e63946', '#ff8c42', '#ffd166', '#00e676'],
      borderWidth: 3,
      borderColor: '#0d1421',
      hoverOffset: 6
    }]
  },
  options: {
    cutout: '68%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#cdd6f4', padding: 14, boxWidth: 12, font: { size: 12 } }
      }
    }
  }
});

// ── MITRE Radar ──────────────────────────────────────────────────────────────
new Chart(document.getElementById('radarChart'), {
  type: 'radar',
  data: {
    labels: RLBL,
    datasets: [{
      label: 'Findings',
      data: RDAT,
      backgroundColor: 'rgba(230,57,70,0.12)',
      borderColor: '#e63946',
      pointBackgroundColor: '#e63946',
      pointBorderColor: '#080c14',
      pointRadius: 4,
      borderWidth: 2,
      fill: true
    }]
  },
  options: {
    scales: {
      r: {
        min: 0,
        grid: { color: '#1e2d45' },
        angleLines: { color: '#1e2d45' },
        ticks: {
          color: '#6e7fa3',
          backdropColor: 'transparent',
          stepSize: 1,
          font: { size: 9 }
        },
        pointLabels: { color: '#cdd6f4', font: { size: 10 } }
      }
    },
    plugins: { legend: { display: false } }
  }
});

// ── Attack Path Bar ──────────────────────────────────────────────────────────
if (PLBL.length > 0) {
  new Chart(document.getElementById('pathChart'), {
    type: 'bar',
    data: {
      labels: PLBL,
      datasets: [{
        data: PSCR,
        backgroundColor: PCLR.map(function(c) { return c + 'cc'; }),
        borderColor: PCLR,
        borderWidth: 1,
        borderRadius: 6,
        borderSkipped: false
      }]
    },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#6e7fa3', font: { size: 11 } },
          grid: { color: '#1e2d45' }
        },
        y: {
          ticks: { color: '#cdd6f4', font: { size: 10 } },
          grid: { display: false }
        }
      }
    }
  });
}

// ── Finding Filter ───────────────────────────────────────────────────────────
function filt(sev, btn) {
  document.querySelectorAll('.fb').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  document.querySelectorAll('.fi').forEach(function(el) {
    el.style.display = (sev === 'all' || el.dataset.sev === sev) ? '' : 'none';
  });
}

// ── Copy code on click ───────────────────────────────────────────────────────
document.querySelectorAll('.steps code').forEach(function(el) {
  el.title = 'Click to copy';
  el.addEventListener('click', function() {
    navigator.clipboard.writeText(el.innerText).then(function() {
      var old = el.style.background;
      el.style.background = '#00d4ff22';
      setTimeout(function() { el.style.background = old; }, 600);
    });
  });
});

// ── Animate likelihood bars ──────────────────────────────────────────────────
document.querySelectorAll('.lbar-fill').forEach(function(el) {
  var w = el.dataset.w;
  setTimeout(function() { el.style.width = w + '%'; }, 300);
});
"""


# ── Reporter class ────────────────────────────────────────────────────────────
class HTMLReporter:
    def __init__(self, prediction, findings, recommendations, scan_results):
        self.p = prediction
        self.findings = findings
        self.recs = recommendations
        self.scan = scan_results

    def write(self, output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(self._build())
        return output_path

    # ── Main builder ─────────────────────────────────────────────────────────
    def _build(self) -> str:
        p = self.p
        sys_info = self.scan.get("system", {}).get("os_info", {})
        ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        score    = p.get("overall_score", 0)
        rl       = p.get("risk_level", "Unknown")
        rc       = SEVERITY_COLOR.get(rl, "#888")
        host     = sys_info.get("hostname", "Unknown")

        from config import ATTACK_TACTICS
        cats      = p.get("stats", {}).get("findings_by_category", {})
        top_paths = p.get("top_attack_paths", [])
        attacker  = p.get("most_likely_attacker", {})

        # Chart JSON data (injected into JS)
        j_sev  = json.dumps([p.get("critical_count",0), p.get("high_count",0),
                              p.get("medium_count",0),  p.get("low_count",0)])
        j_rlbl = json.dumps(ATTACK_TACTICS)
        j_rdat = json.dumps([cats.get(t, 0) for t in ATTACK_TACTICS])
        j_plbl = json.dumps([a["name"][:32] for a in top_paths])
        j_pscr = json.dumps([a["risk_score"] for a in top_paths])
        j_pclr = json.dumps([SEVERITY_COLOR.get(a.get("impact",""), "#888") for a in top_paths])

        # Data bootstrap for JS
        js_data = (
            f"const SCORE={score};"
            f"const SEV={j_sev};"
            f"const RLBL={j_rlbl};"
            f"const RDAT={j_rdat};"
            f"const PLBL={j_plbl};"
            f"const PSCR={j_pscr};"
            f"const PCLR={j_pclr};"
        )

        # Pre-build sections
        chips    = "".join(f'<span class="chip">{t}</span>' for t in attacker.get("techniques", []))
        f_html   = self._findings_html()
        ap_html  = self._paths_html()
        rec_html = self._recs_html()
        gen_html = "".join(self._gen_rec(r) for r in self.recs.get("general", []))

        n_c  = p.get("critical_count", 0)
        n_h  = p.get("high_count", 0)
        n_m  = p.get("medium_count", 0)
        n_l  = p.get("low_count", 0)
        tot  = p.get("total_findings", 0)
        n_ap = p.get("total_attack_paths", 0)
        os_s = f"{sys_info.get('os','Windows')} {sys_info.get('release','')}"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PredatorEye &mdash; {self._e(host)}</title>
<style>{_CSS}</style>
</head>
<body>

<header>
  <div class="hi">
    <div class="brand">
      {EYE_SVG}
      <div>
        <div class="bname">Predator<span>Eye</span></div>
        <div class="bsub">See What Attackers See</div>
      </div>
    </div>
    <div class="hmeta">
      <div class="hhost">{self._e(host)}</div>
      <div class="htime">{self._e(os_s)} &bull; Scanned {ts}</div>
    </div>
  </div>
</header>

<main>

<!-- ── Hero ── -->
<section class="hero">
  <div class="gw">
    <canvas id="gauge" width="260" height="160"></canvas>
    <div class="gl">
      <div class="gscore" style="color:{rc}">{score}</div>
      <div class="g100">/ 100</div>
      <div class="glevel" style="color:{rc}">{rl}</div>
    </div>
  </div>
  <div class="hinfo">
    <h1>Security Assessment Report</h1>
    <p class="hsub">Found <b>{tot} findings</b> across <b>{n_ap} predicted attack paths</b></p>
    <div class="pills">
      <div class="pill pc"><b>{n_c}</b><span>Critical</span></div>
      <div class="pill ph"><b>{n_h}</b><span>High</span></div>
      <div class="pill pm"><b>{n_m}</b><span>Medium</span></div>
      <div class="pill pl"><b>{n_l}</b><span>Low</span></div>
    </div>
  </div>
</section>

<!-- ── Charts ── -->
<section class="charts">
  <div class="cc">
    <div class="ctitle">Severity Breakdown</div>
    <canvas id="sevChart" height="220"></canvas>
  </div>
  <div class="cc">
    <div class="ctitle">MITRE ATT&amp;CK Tactic Coverage</div>
    <canvas id="radarChart" height="220"></canvas>
  </div>
  <div class="cc">
    <div class="ctitle">Attack Path Risk Scores</div>
    <canvas id="pathChart" height="220"></canvas>
  </div>
</section>

<!-- ── System + Attacker ── -->
<section class="ig">
  <div class="card">
    <div class="ct">System Information</div>
    <table class="itbl">
      <tr><td>Hostname</td><td><b>{self._e(host)}</b></td></tr>
      <tr><td>OS</td><td>{self._e(os_s)}</td></tr>
      <tr><td>User</td><td>{self._e(sys_info.get('current_user','N/A'))}</td></tr>
      <tr><td>Architecture</td><td>{self._e(sys_info.get('machine','N/A'))}</td></tr>
      <tr><td>Scanned</td><td>{ts}</td></tr>
    </table>
  </div>
  <div class="card atk-card">
    <div class="ct">Most Likely Threat Actor</div>
    <div class="aprof">{self._e(attacker.get('profile','Unknown'))}</div>
    <div class="amot"><span>Motivation: </span><b style="color:#e63946">{self._e(attacker.get('motivation','Unknown'))}</b></div>
    <div class="chips">{chips}</div>
  </div>
</section>

<!-- ── Attack Paths ── -->
<section>
  <div class="sh">Predicted Attack Paths</div>
  {ap_html}
</section>

<!-- ── Findings ── -->
<section>
  <div class="sh">Security Findings</div>
  <div class="fbar">
    <button class="fb active" onclick="filt('all',this)">All &nbsp;({tot})</button>
    <button class="fb" onclick="filt('Critical',this)">Critical &nbsp;({n_c})</button>
    <button class="fb" onclick="filt('High',this)">High &nbsp;({n_h})</button>
    <button class="fb" onclick="filt('Medium',this)">Medium &nbsp;({n_m})</button>
    <button class="fb" onclick="filt('Low',this)">Low &nbsp;({n_l})</button>
  </div>
  <div id="fl">{f_html}</div>
</section>

<!-- ── Recommendations ── -->
<section>
  <div class="sh">Prevention &amp; Remediation</div>
  <div class="sub-sh">Specific Recommendations</div>
  {rec_html}
  <div class="sub-sh" style="margin-top:1.5rem">General Security Hardening</div>
  {gen_html}
</section>

</main>

<footer>
  PredatorEye v1.0.0 &bull; {ts} &bull; For authorised use only
</footer>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>{js_data}{_JS_LOGIC}</script>
</body>
</html>"""

    # ── Attack Path Flow ──────────────────────────────────────────────────────
    def _paths_html(self) -> str:
        paths = self.p.get("top_attack_paths", [])
        if not paths:
            return '<div class="card" style="text-align:center;color:#6e7fa3;padding:2rem">No significant attack paths identified.</div>'

        parts = []
        for i, ap in enumerate(paths):
            sev    = ap.get("impact", "Medium")
            rc     = SEVERITY_COLOR.get(sev, "#888")
            like   = int(ap.get("likelihood", 0) * 100)
            rscore = ap.get("risk_score", 0)

            # Flow steps
            steps  = ap.get("steps", [])
            flow_items = []
            for j, s in enumerate(steps):
                title = (s.get("title","") if isinstance(s, dict) else str(s))[:36]
                ssev  = s.get("severity","") if isinstance(s, dict) else ""
                sc    = SEVERITY_COLOR.get(ssev, "#1e2d45")
                flow_items.append(
                    f'<div class="flow-step" style="border-color:{sc}44">'
                    f'<div class="sn">Step {j+1}</div>'
                    f'<div class="st" title="{self._e(title)}">{self._e(title)}</div>'
                    f'</div>'
                )
                if j < len(steps) - 1:
                    flow_items.append('<div class="flow-arrow">&#8594;</div>')

            flow_html = "".join(flow_items) if flow_items else "<em style='color:#6e7fa3'>No steps</em>"

            parts.append(f"""
<div class="ap" style="border-left:4px solid {rc}40">
  <div class="ap-hdr">
    <div>
      <span style="color:#6e7fa3;font-size:.78rem;margin-right:.4rem">#{i+1}</span>
      <span class="ap-title">{self._e(ap.get('name',''))}</span>
    </div>
    <div class="ap-meta">
      {_badge(sev)}
      <span class="ap-risk" style="color:{rc}">Risk&nbsp;{rscore}</span>
    </div>
  </div>
  <div class="ap-desc">{self._e(ap.get('description',''))}</div>
  <div class="flow">{flow_html}</div>
  <div class="lbar">
    <div class="lbar-fill" data-w="{like}" style="width:0%;background:{rc}"></div>
  </div>
  <div class="lbar-lbl">Likelihood: {like}%</div>
</div>""")

        return "\n".join(parts)

    # ── Findings ─────────────────────────────────────────────────────────────
    def _findings_html(self) -> str:
        if not self.findings:
            return '<div class="card" style="text-align:center;color:#6e7fa3;padding:2rem">No findings detected.</div>'

        parts = []
        for f in self.findings:
            det_json = json.dumps(f.details, indent=2, default=str)
            det_html = (
                f'<details><summary>Technical details</summary>'
                f'<pre>{self._e(det_json)}</pre></details>'
            ) if f.details else ""

            parts.append(f"""
<div class="fi" data-sev="{f.severity}" style="border-left-color:{SEVERITY_COLOR.get(f.severity,'#1e2d45')}">
  <div class="fi-hdr">
    <span class="fid">{f.id}</span>
    {_badge(f.severity)}
    <span class="ftitle">{self._e(f.title)}</span>
  </div>
  <div class="fdesc">{self._e(f.description)}</div>
  <div class="fcat">MITRE ATT&amp;CK: {self._e(f.category)}</div>
  {det_html}
</div>""")

        return "\n".join(parts)

    # ── Specific recommendations ─────────────────────────────────────────────
    def _recs_html(self) -> str:
        recs = self.recs.get("specific", [])
        if not recs:
            return '<div style="color:#6e7fa3">No specific recommendations generated.</div>'
        return "".join(self._spec_rec(r) for r in recs)

    def _spec_rec(self, rec: dict) -> str:
        sev  = rec.get("severity", "")
        cls  = {"Critical":"rc","High":"rh","Medium":"rm"}.get(sev, "")
        steps = "".join(f"<li>{self._fmt(s)}</li>" for s in rec.get("steps", []))
        ref  = f'<div class="rec-ref">Ref: {self._e(rec["reference"])}</div>' if rec.get("reference") else ""
        return f"""
<div class="rec {cls}">
  <div class="rec-hdr">
    {_badge(sev)}
    <span class="rec-title">{self._e(rec.get('finding_title',''))}</span>
    <span class="rec-fid">{rec.get('finding_id','')}</span>
  </div>
  <ul class="steps">{steps}</ul>
  {ref}
</div>"""

    def _gen_rec(self, rec: dict) -> str:
        steps = "".join(f"<li>{self._fmt(s)}</li>" for s in rec.get("steps", []))
        return f"""
<div class="rec">
  <div class="rec-hdr"><span class="rec-title" style="color:#00d4ff">{self._e(rec.get('title',''))}</span></div>
  <ul class="steps">{steps}</ul>
</div>"""

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _fmt(self, text: str) -> str:
        escaped = self._e(text)
        escaped = re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped)
        return escaped

    @staticmethod
    def _e(text: str) -> str:
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
