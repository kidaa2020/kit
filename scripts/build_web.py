#!/usr/bin/env python3
"""
ReconKit — Genera web estática de resultados para GitHub Pages
"""
import json
import os
import shutil
from pathlib import Path
from datetime import datetime

OUT_DIR  = Path("web-out")
REPO     = os.environ.get("GITHUB_REPOSITORY", "user/reconkit")
RUN_ID   = os.environ.get("GITHUB_RUN_ID", "")
OUT_DIR.mkdir(exist_ok=True)

# ── Cargar datos del scan ──────────────────────────────────

latest_ptr = Path("audits/latest.txt")
data = {}
if latest_ptr.exists():
    json_path = Path(latest_ptr.read_text().strip())
    if json_path.exists():
        data = json.loads(json_path.read_text())

# ── Cargar historial de scans anteriores ──────────────────

history = []
for jf in sorted(Path("audits").glob("*/*/results.json"), reverse=True):
    try:
        d = json.loads(jf.read_text())
        history.append({"target": d.get("target",""), "date": d.get("date",""),
                        "severity": d.get("severity",""), "run_id": d.get("run_id","")})
    except Exception:
        pass

# ── Cargar SUMMARY.md del último scan ─────────────────────

summary_md = ""
if latest_ptr.exists():
    summary_file = Path(latest_ptr.read_text().strip()).parent / "SUMMARY.md"
    if summary_file.exists():
        summary_md = summary_file.read_text()

ai_report = data.get("ai_report", "")

# ── Funciones helper ──────────────────────────────────────

def sev_class(sev):
    if "CRÍTICO" in sev: return "crit"
    if "ATENCIÓN" in sev: return "high"
    if "REVISAR"  in sev: return "med"
    return "ok"

def badge(n, label, cls=""):
    return f'<div class="badge {cls}"><span class="badge-num">{n}</span><span class="badge-label">{label}</span></div>'

def history_rows():
    rows = ""
    for h in history[:15]:
        sc = sev_class(h.get("severity",""))
        rows += f"""
        <tr>
          <td><code>{h.get('target','')}</code></td>
          <td>{h.get('date','')}</td>
          <td><span class="sev {sc}">{h.get('severity','')}</span></td>
          <td><a href="https://github.com/{REPO}/actions/runs/{h.get('run_id','')}" target="_blank">#{h.get('run_id','')[:8]}</a></td>
        </tr>"""
    return rows or "<tr><td colspan='4'>Sin scans anteriores</td></tr>"

def endpoints_html():
    cats = data.get("endpoints_by_cat", {})
    out  = ""
    for cat, eps in cats.items():
        if eps:
            items = "".join(f"<li><code>{e}</code></li>" for e in eps[:20])
            out  += f"<div class='ep-group'><h4>{cat} <span>({len(eps)})</span></h4><ul>{items}</ul></div>"
    return out or "<p class='empty'>Sin endpoints encontrados.</p>"

def secrets_html():
    st = data.get("secrets_by_type", {})
    if not st:
        return "<p class='empty ok-text'>✅ No se encontraron secrets.</p>"
    out = ""
    for stype, items in st.items():
        icon = "🔴" if stype in ("AWS Access Key","GitHub Token","AWS Secret Key") else "🟠"
        rows = "".join(f"<li><code>{i[:100]}</code></li>" for i in items[:5])
        out += f"<div class='secret-group'><h4>{icon} {stype} <span>({len(items)})</span></h4><ul>{rows}</ul></div>"
    return out

def fuzz_html():
    hits = data.get("fuzz_hits", [])
    if not hits:
        return "<p class='empty'>Sin rutas encontradas.</p>"
    rows = ""
    for h in hits[:30]:
        status = h.get("status", "-")
        cls = "s200" if str(status).startswith("2") else ("s301" if str(status).startswith("3") else "s403")
        rows += f"<tr><td><span class='status {cls}'>{status}</span></td><td><code>{h.get('url','')}</code></td><td>{h.get('length','-')} B</td></tr>"
    return f"<table><thead><tr><th>Código</th><th>URL</th><th>Tamaño</th></tr></thead><tbody>{rows}</tbody></table>"

def ports_html():
    lines = data.get("port_lines", [])
    interesting = {"8080","8443","9200","6379","27017","5432","3306","2375","9000","3000","5000","21","23","25"}
    if not lines:
        return "<p class='empty'>Sin puertos encontrados.</p>"
    rows = ""
    for l in lines[:30]:
        import re
        pn = re.match(r"(\d+)/", l)
        warn = " warn-port" if pn and pn.group(1) in interesting else ""
        rows += f"<tr class='{warn}'><td><code>{l}</code></td></tr>"
    return f"<table><tbody>{rows}</tbody></table>"

def alive_html():
    lines = data.get("alive_lines", [])
    if not lines:
        return "<p class='empty'>Sin subdominios vivos.</p>"
    items = "".join(f"<li><code>{l}</code></li>" for l in lines[:30])
    return f"<ul class='alive-list'>{items}</ul>"

def ai_html():
    if not ai_report:
        return "<p class='empty'>Módulo IA no ejecutado o sin API key configurada.</p>"
    # Convertir markdown básico a HTML
    import re
    html = ai_report
    html = re.sub(r"### (.+)", r"<h4>\1</h4>", html)
    html = re.sub(r"## (.+)",  r"<h3>\1</h3>", html)
    html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)
    html = re.sub(r"^(HALLAZGO|SEVERIDAD|URL|DESCRIPCIÓN|EVIDENCIA|RECOMENDACIÓN|SECRET|TIPO|IMPACTO|VÁLIDO):", 
                  r"<strong>\1:</strong>", html, flags=re.MULTILINE)
    html = html.replace("---", "<hr>")
    html = re.sub(r"\n{2,}", "</p><p>", html)
    return f"<div class='ai-content'><p>{html}</p></div>"


# ── Generar index.html ────────────────────────────────────

sc   = sev_class(data.get("severity", ""))
now  = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
repo = REPO

html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ReconKit — {data.get('target','Sin target')}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600&display=swap');
:root{{
  --bg:#0a0c0f;--bg2:#10141a;--bg3:#161c24;--border:#1e2730;--border2:#2a3545;
  --green:#00d97e;--cyan:#00b4d8;--yellow:#f5c400;--red:#ff4757;--purple:#a162f6;
  --text:#c8d3de;--text-dim:#6b7a8d;--accent:#3d7eff;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px;line-height:1.6}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{color:var(--cyan)}}
code{{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg3);padding:2px 6px;border-radius:3px;word-break:break-all}}

/* ── Nav ── */
nav{{position:sticky;top:0;z-index:100;background:var(--bg2);border-bottom:1px solid var(--border);
     display:flex;align-items:center;gap:12px;padding:0 20px;height:48px}}
.logo{{font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--green);font-size:15px}}
.logo span{{color:var(--text-dim);font-weight:300}}
.nav-links{{display:flex;gap:16px;margin-left:auto}}
.nav-links a{{font-size:12px;color:var(--text-dim);padding:4px 8px;border-radius:4px;transition:.15s}}
.nav-links a:hover{{color:var(--text);background:var(--bg3)}}
.run-badge{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text-dim);
            background:var(--bg3);border:1px solid var(--border2);border-radius:4px;padding:3px 8px}}

/* ── Layout ── */
.container{{max-width:1100px;margin:0 auto;padding:24px 16px}}
section{{margin-bottom:40px}}

/* ── Hero ── */
.hero{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:28px;margin-bottom:32px}}
.hero-target{{font-family:'JetBrains Mono',monospace;font-size:22px;font-weight:700;color:var(--text);margin-bottom:6px}}
.hero-meta{{font-size:12px;color:var(--text-dim);margin-bottom:20px}}
.sev-banner{{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:6px;
             font-weight:600;font-size:13px;margin-bottom:20px}}
.sev-banner.crit{{background:rgba(255,71,87,.12);border:1px solid rgba(255,71,87,.4);color:var(--red)}}
.sev-banner.high{{background:rgba(255,121,63,.12);border:1px solid rgba(255,121,63,.4);color:#ff793f}}
.sev-banner.med{{background:rgba(245,196,0,.1);border:1px solid rgba(245,196,0,.3);color:var(--yellow)}}
.sev-banner.ok{{background:rgba(0,217,126,.08);border:1px solid rgba(0,217,126,.3);color:var(--green)}}

.badges{{display:flex;flex-wrap:wrap;gap:10px}}
.badge{{background:var(--bg3);border:1px solid var(--border2);border-radius:8px;
        padding:10px 14px;display:flex;flex-direction:column;align-items:center;min-width:90px}}
.badge.alert{{border-color:rgba(255,71,87,.4);background:rgba(255,71,87,.06)}}
.badge.warn{{border-color:rgba(245,196,0,.3);background:rgba(245,196,0,.05)}}
.badge.ok2{{border-color:rgba(0,217,126,.3);background:rgba(0,217,126,.05)}}
.badge-num{{font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;line-height:1}}
.badge.alert .badge-num{{color:var(--red)}}
.badge.warn  .badge-num{{color:var(--yellow)}}
.badge.ok2   .badge-num{{color:var(--green)}}
.badge-label{{font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;margin-top:4px;text-align:center}}

/* ── Section headers ── */
.sec-header{{display:flex;align-items:center;gap:10px;margin-bottom:14px;
             padding-bottom:10px;border-bottom:1px solid var(--border)}}
.sec-header h2{{font-size:16px;font-weight:600}}
.sec-count{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);
            background:var(--bg3);border:1px solid var(--border2);border-radius:10px;padding:2px 8px}}

/* ── Card ── */
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px}}

/* ── Tables ── */
table{{width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace;font-size:12px}}
th{{text-align:left;padding:8px 10px;border-bottom:2px solid var(--border2);color:var(--text-dim);
    font-size:10px;text-transform:uppercase;letter-spacing:.06em}}
td{{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr.warn-port td{{color:var(--yellow)}}
.status{{padding:2px 7px;border-radius:3px;font-size:11px;font-weight:700}}
.s200{{background:rgba(0,217,126,.15);color:var(--green)}}
.s301{{background:rgba(61,126,255,.15);color:var(--accent)}}
.s403{{background:rgba(245,196,0,.12);color:var(--yellow)}}

/* ── Severity in history ── */
.sev{{padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600}}
.sev.crit{{background:rgba(255,71,87,.15);color:var(--red)}}
.sev.high{{background:rgba(255,121,63,.12);color:#ff793f}}
.sev.med{{background:rgba(245,196,0,.1);color:var(--yellow)}}
.sev.ok{{background:rgba(0,217,126,.1);color:var(--green)}}

/* ── Lists ── */
ul{{list-style:none;padding:0}}
.alive-list li{{padding:5px 0;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:12px}}
.alive-list li:last-child{{border-bottom:none}}
.ep-group,.secret-group{{margin-bottom:16px}}
.ep-group h4,.secret-group h4{{font-size:12px;color:var(--text-dim);margin-bottom:8px;font-family:'JetBrains Mono',monospace}}
.ep-group h4 span,.secret-group h4 span{{color:var(--text-dim);font-weight:400}}
.ep-group ul li,.secret-group ul li{{padding:4px 0;font-family:'JetBrains Mono',monospace;font-size:11px;
                                     border-bottom:1px solid var(--border)}}

/* ── AI ── */
.ai-content{{font-size:13px;line-height:1.7}}
.ai-content h3{{color:var(--cyan);margin:16px 0 8px;font-size:14px}}
.ai-content h4{{color:var(--text-dim);margin:12px 0 6px;font-size:13px}}
.ai-content hr{{border:none;border-top:1px solid var(--border);margin:16px 0}}
.ai-content strong{{color:var(--yellow)}}

/* ── Misc ── */
.empty{{color:var(--text-dim);font-style:italic;font-size:13px}}
.ok-text{{color:var(--green)!important;font-style:normal!important}}
.updated{{font-size:11px;color:var(--text-dim);text-align:right;margin-top:32px;padding-top:16px;border-top:1px solid var(--border)}}
.tabs{{display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap}}
.tab-btn{{padding:6px 14px;border-radius:5px;border:1px solid var(--border2);background:var(--bg3);
          color:var(--text-dim);font-size:12px;cursor:pointer;transition:.15s;font-family:'JetBrains Mono',monospace}}
.tab-btn.active,.tab-btn:hover{{border-color:var(--accent);color:var(--accent)}}
.tab-pane{{display:none}}.tab-pane.active{{display:block}}

@media(max-width:600px){{
  .badges{{gap:8px}}
  .badge{{min-width:75px;padding:8px 10px}}
  .badge-num{{font-size:20px}}
  .nav-links{{display:none}}
  .hero{{padding:16px}}
}}
</style>
</head>
<body>

<nav>
  <div class="logo">Recon<span>Kit</span></div>
  <div class="nav-links">
    <a href="#subdominios">Subdominios</a>
    <a href="#puertos">Puertos</a>
    <a href="#javascript">JavaScript</a>
    <a href="#web">Web</a>
    <a href="#ia">IA</a>
    <a href="#historial">Historial</a>
  </div>
  <span class="run-badge">
    <a href="https://github.com/{repo}/actions/runs/{RUN_ID}" target="_blank" style="color:inherit">
      Run #{RUN_ID[:8] if RUN_ID else 'local'}
    </a>
  </span>
</nav>

<div class="container">

  <!-- ── Hero ── -->
  <div class="hero">
    <div class="hero-target">🎯 {data.get('target', 'Sin target')}</div>
    <div class="hero-meta">{data.get('date','—')} · GitHub Actions · 
      <a href="https://github.com/{repo}/actions" target="_blank">ver workflow</a>
    </div>
    <div class="sev-banner {sc}">{data.get('severity','—')}</div>
    <div class="badges">
      {badge(data.get('subdomains_found',0), 'Subdominios', 'ok2')}
      {badge(data.get('subdomains_alive',0), 'Vivos', 'ok2')}
      {badge(data.get('ports_open',0), 'Puertos', 'warn' if data.get('interesting_services') else '')}
      {badge(data.get('js_files',0), 'JS', '')}
      {badge(data.get('endpoints_found',0), 'Endpoints', '')}
      {badge(data.get('secrets_found',0), 'Secrets', 'alert' if data.get('secrets_found',0) > 0 else 'ok2')}
      {badge(data.get('vuln_hints',0), 'Web hits', 'warn' if data.get('vuln_hints',0) > 0 else '')}
    </div>
  </div>

  <!-- ── Subdominios ── -->
  <section id="subdominios">
    <div class="sec-header">
      <h2>🌐 Subdominios</h2>
      <span class="sec-count">{data.get('subdomains_alive',0)} vivos de {data.get('subdomains_found',0)}</span>
    </div>
    <div class="card">{alive_html()}</div>
  </section>

  <!-- ── Puertos ── -->
  <section id="puertos">
    <div class="sec-header">
      <h2>🔌 Puertos abiertos</h2>
      <span class="sec-count">{data.get('ports_open',0)} abiertos</span>
    </div>
    <div class="card">{ports_html()}</div>
  </section>

  <!-- ── JavaScript ── -->
  <section id="javascript">
    <div class="sec-header">
      <h2>⚡ JavaScript</h2>
      <span class="sec-count">{data.get('js_files',0)} archivos · {data.get('endpoints_found',0)} endpoints · {data.get('secrets_found',0)} secrets</span>
    </div>
    <div class="tabs">
      <button class="tab-btn active" onclick="showTab('secrets','js')">🔑 Secrets</button>
      <button class="tab-btn" onclick="showTab('endpoints','js')">🔗 Endpoints</button>
    </div>
    <div class="card">
      <div class="tab-pane active" id="js-secrets">{secrets_html()}</div>
      <div class="tab-pane" id="js-endpoints">{endpoints_html()}</div>
    </div>
  </section>

  <!-- ── Web ── -->
  <section id="web">
    <div class="sec-header">
      <h2>🔍 Análisis Web</h2>
      <span class="sec-count">{data.get('vuln_hints',0)} hallazgos</span>
    </div>
    <div class="card">{fuzz_html()}</div>
  </section>

  <!-- ── IA ── -->
  <section id="ia">
    <div class="sec-header">
      <h2>🤖 Análisis IA</h2>
      <span class="sec-count">OpenRouter · openrouter/free</span>
    </div>
    <div class="card">{ai_html()}</div>
  </section>

  <!-- ── Historial ── -->
  <section id="historial">
    <div class="sec-header">
      <h2>📋 Historial de scans</h2>
      <span class="sec-count">{len(history)} scans</span>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>Target</th><th>Fecha</th><th>Severidad</th><th>Run</th></tr></thead>
        <tbody>{history_rows()}</tbody>
      </table>
    </div>
  </section>

  <div class="updated">Generado: {now} · 
    <a href="https://github.com/{repo}" target="_blank">{repo}</a>
  </div>

</div>

<script>
function showTab(name, group) {{
  document.querySelectorAll(`#${{group}}-secrets, #${{group}}-endpoints`).forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`${{group}}-${{name}}`).classList.add('active');
  event.target.classList.add('active');
}}
</script>
</body>
</html>"""

# Escribir index.html
(OUT_DIR / "index.html").write_text(html)

# Copiar resultados JSON también
shutil.copy2(latest_ptr.read_text().strip(), OUT_DIR / "results.json") if latest_ptr.exists() else None

print(f"✔ Web generada en {OUT_DIR}/index.html")
