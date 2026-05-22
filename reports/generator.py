import json
import os
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "output")

_SEV = {
    "CRITICAL": {"color": "#b91c1c", "bg": "#fef2f2", "border": "#fecaca", "dot": "#ef4444"},
    "HIGH":     {"color": "#c2410c", "bg": "#fff7ed", "border": "#fed7aa", "dot": "#f97316"},
    "MEDIUM":   {"color": "#a16207", "bg": "#fefce8", "border": "#fde68a", "dot": "#eab308"},
    "LOW":      {"color": "#1d4ed8", "bg": "#eff6ff", "border": "#bfdbfe", "dot": "#3b82f6"},
}


def to_json(results: dict, pretty: bool = True) -> str:
    """Serializes the full scan results dict to a JSON string."""
    return json.dumps(results, indent=2 if pretty else None, ensure_ascii=False)


def save_json(results: dict, filepath: str | None = None) -> str:
    """Saves results as JSON. Returns the absolute path."""
    _ensure_output_dir()
    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(to_json(results))
    return filepath


def save_html(results: dict, filepath: str | None = None) -> str:
    """Generates a self-contained HTML report and saves it. Returns the absolute path."""
    _ensure_output_dir()
    if filepath is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(REPORTS_DIR, f"report_{timestamp}.html")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(_build_html(results))
    return filepath


def to_html(results: dict) -> str:
    """Returns the HTML report as a string (without saving to disk)."""
    return _build_html(results)


def _ensure_output_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)


# ── HTML builder ──────────────────────────────────────────────────────────────

def _build_html(results: dict) -> str:
    network    = results.get("network", "N/A")
    scanned_at = results.get("scanned_at", "N/A")
    hosts      = results.get("hosts", [])
    summary    = results.get("summary", {})
    total      = results.get("total_hosts", len(hosts))

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Network Analyzer — Reporte</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', 'Segoe UI', sans-serif;
      background: #f8fafc;
      color: #1e293b;
      min-height: 100vh;
    }}
    .font-mono {{ font-family: 'JetBrains Mono', monospace; }}

    /* ── layout ── */
    header {{
      background: #f8fafc;
      border-bottom: 1px solid #e2e8f0;
      padding: 0 2rem;
      height: 4rem;
      display: flex;
      align-items: center;
      gap: .75rem;
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    .logo {{
      width: 2rem; height: 2rem;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      border-radius: .5rem;
      display: flex; align-items: center; justify-content: center;
      color: white; font-size: .9rem; font-weight: 700;
    }}
    header h1 {{ font-size: .95rem; font-weight: 600; color: #0f172a; }}
    main {{ max-width: 900px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }}

    /* ── meta bar ── */
    .meta-bar {{
      display: flex; flex-wrap: wrap; align-items: flex-start;
      justify-content: space-between; gap: 1rem;
      border-bottom: 1px solid #e2e8f0; padding-bottom: 1.25rem; margin-bottom: 2rem;
    }}
    .meta-bar h2 {{ font-size: 1.5rem; font-weight: 700; color: #0f172a; }}
    .meta-bar p  {{ font-size: .8rem; color: #64748b; margin-top: .2rem; }}
    .meta-tag {{
      display: inline-block; background: #f1f5f9; border: 1px solid #e2e8f0;
      border-radius: .375rem; padding: .15rem .5rem;
      font-family: 'JetBrains Mono', monospace; font-size: .75rem; color: #334155;
    }}

    /* ── summary grid ── */
    .summary-grid {{
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem;
    }}
    @media (max-width: 600px) {{ .summary-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    .summary-card {{
      background: white; border: 1px solid #e2e8f0; border-radius: 1rem;
      padding: 1.25rem 1.25rem 1rem; position: relative; overflow: hidden;
    }}
    .summary-card .dot-label {{ display: flex; align-items: center; gap: .5rem; margin-bottom: .6rem; }}
    .summary-card .dot {{ width: .6rem; height: .6rem; border-radius: 50%; }}
    .summary-card .sev-name {{ font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; color: #64748b; }}
    .summary-card .count {{ font-size: 2rem; font-weight: 900; color: #0f172a; }}

    /* ── section heading ── */
    .section-heading {{
      display: flex; align-items: center; gap: .5rem;
      font-size: 1.1rem; font-weight: 700; color: #0f172a;
      margin-bottom: 1.25rem;
    }}
    .section-heading svg {{ color: #94a3b8; }}

    /* ── host cards ── */
    .host-card {{
      background: white; border: 1px solid #e2e8f0; border-radius: 1rem;
      overflow: hidden; margin-bottom: 1.5rem;
      box-shadow: 0 1px 4px rgba(0,0,0,.04);
    }}
    .host-head {{
      background: #f8fafc; border-bottom: 1px solid #e2e8f0;
      padding: 1.1rem 1.25rem;
      display: flex; flex-wrap: wrap; align-items: center;
      justify-content: space-between; gap: .75rem;
    }}
    .host-info {{ display: flex; align-items: center; gap: 1rem; }}
    .host-icon {{
      width: 3rem; height: 3rem; background: white;
      border: 1px solid #e2e8f0; border-radius: .75rem;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.3rem;
    }}
    .host-ip {{ font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; font-weight: 700; color: #2563eb; }}
    .host-badges {{ display: flex; flex-wrap: wrap; gap: .4rem; margin-top: .25rem; }}
    .chip {{
      display: inline-block; padding: .15rem .5rem; border-radius: .375rem;
      font-size: .7rem; font-weight: 500; border: 1px solid;
    }}
    .chip-gray  {{ background: #f1f5f9; border-color: #e2e8f0; color: #475569; font-family: 'JetBrains Mono', monospace; }}
    .chip-blue  {{ background: #eff6ff; border-color: #bfdbfe; color: #1d4ed8; }}
    .status-up {{
      display: flex; align-items: center; gap: .4rem;
      background: white; border: 1px solid #d1fae5;
      border-radius: .5rem; padding: .3rem .75rem;
      font-size: .7rem; font-weight: 700; color: #059669; text-transform: uppercase;
    }}
    .status-up .dot {{ width: .5rem; height: .5rem; border-radius: 50%; background: #10b981; }}

    /* ── ports table ── */
    .host-body {{ padding: 1.25rem; }}
    .table-wrap {{ border: 1px solid #f1f5f9; border-radius: .75rem; overflow: hidden; overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .85rem; min-width: 480px; }}
    thead tr {{ background: #f8fafc; border-bottom: 1px solid #f1f5f9; }}
    th {{ padding: .6rem 1rem; text-align: left; font-size: .7rem; font-weight: 700;
          text-transform: uppercase; letter-spacing: .06em; color: #64748b; }}
    tbody tr {{ border-bottom: 1px solid #f8fafc; transition: background .1s; }}
    tbody tr:last-child {{ border-bottom: none; }}
    td {{ padding: .75rem 1rem; vertical-align: top; color: #334155; }}
    td.port {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #0f172a; font-size: .85rem; }}
    .state-badge {{
      display: inline-block; padding: .2rem .6rem; border-radius: .375rem;
      font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
      background: #f0fdf4; border: 1px solid #bbf7d0; color: #15803d;
    }}

    /* ── vuln alert ── */
    .vuln-alert {{
      display: flex; gap: .6rem; align-items: flex-start;
      border: 1px solid; border-radius: .5rem; padding: .6rem .75rem; margin-top: .5rem;
    }}
    .vuln-icon {{ font-size: 1rem; line-height: 1.4; flex-shrink: 0; }}
    .vuln-sev  {{ font-size: .65rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; display: block; margin-bottom: .15rem; }}
    .vuln-title {{ font-size: .78rem; font-weight: 600; display: block; margin-bottom: .15rem; }}
    .vuln-desc  {{ font-size: .75rem; color: #475569; }}

    /* ── no ports / no vulns ── */
    .no-ports {{ font-size: .85rem; color: #64748b; }}
    .no-vulns  {{ display: flex; align-items: center; gap: .4rem; font-size: .85rem; color: #059669; font-weight: 500; margin-top: .75rem; }}
  </style>
</head>
<body>
  <header>
    <div class="logo">N</div>
    <h1>Network Analyzer</h1>
  </header>

  <main>
    <div class="meta-bar">
      <div>
        <h2>{total} host{"s" if total != 1 else ""} encontrado{"s" if total != 1 else ""}</h2>
        <p>Objetivo: <span class="meta-tag">{network}</span> &nbsp;&bull;&nbsp; {scanned_at}</p>
      </div>
    </div>

    {_render_summary(summary)}

    <div class="section-heading">
      <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round"
          d="M5 12h14M12 5l7 7-7 7"/>
      </svg>
      Hosts Descubiertos
    </div>

    {_render_hosts(hosts)}
  </main>
</body>
</html>"""


def _render_summary(summary: dict) -> str:
    cards = ""
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = summary.get(level, 0)
        s = _SEV[level]
        cards += f"""
        <div class="summary-card">
          <div class="dot-label">
            <span class="dot" style="background:{s['dot']};"></span>
            <span class="sev-name">{level}</span>
          </div>
          <span class="count">{count}</span>
        </div>"""
    return f'<div class="summary-grid">{cards}</div>'


def _render_hosts(hosts: list[dict]) -> str:
    if not hosts:
        return "<p class='no-ports'>No se encontraron hosts activos.</p>"

    cards = []
    for host in hosts:
        ip       = host.get("ip", "")
        mac      = host.get("mac", "")
        hostname = host.get("hostname", "unknown")
        vendor   = host.get("vendor", "")
        ports    = host.get("ports", [])
        vulns    = host.get("vulnerabilities", [])

        vuln_by_port = {v["port"]: v for v in vulns}

        vendor_chip = (
            f'<span class="chip chip-blue">{vendor}</span>'
            if vendor and vendor != "unknown" else ""
        )

        icon = "🍎" if vendor and "apple" in vendor.lower() else (
               "📡" if vendor and ("cisco" in vendor.lower() or "comm" in vendor.lower()) else "🖥")

        port_rows = ""
        for p in ports:
            v = vuln_by_port.get(p["port"])
            alert_html = _render_vuln_alert(v) if v else ""
            port_rows += f"""
            <tr>
              <td class="port">{p['port']}<span style="color:#94a3b8;font-weight:400;">/tcp</span></td>
              <td>{p['service']}</td>
              <td>
                <span class="state-badge">OPEN</span>
                {alert_html}
              </td>
            </tr>"""

        ports_block = f"""
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th>Puerto / Proto</th>
                <th>Servicio</th>
                <th>Estado / Alertas</th>
              </tr></thead>
              <tbody>{port_rows}</tbody>
            </table>
          </div>""" if ports else "<p class='no-ports'>Sin puertos abiertos detectados.</p>"

        no_vulns_block = (
            '<p class="no-vulns">&#10003; Sin vulnerabilidades detectadas</p>'
            if not vulns else ""
        )

        cards.append(f"""
        <div class="host-card">
          <div class="host-head">
            <div class="host-info">
              <div class="host-icon">{icon}</div>
              <div>
                <div class="host-ip">{ip}</div>
                <div class="host-badges">
                  <span class="chip chip-gray">{mac}</span>
                  {vendor_chip}
                  <span class="chip chip-gray" style="font-family:inherit;">{hostname}</span>
                </div>
              </div>
            </div>
            <div class="status-up"><span class="dot"></span>Up</div>
          </div>
          <div class="host-body">
            {ports_block}
            {no_vulns_block}
          </div>
        </div>""")

    return "\n".join(cards)


def _render_vuln_alert(v: dict) -> str:
    sev   = v.get("severity", "LOW")
    s     = _SEV.get(sev, _SEV["LOW"])
    icon  = "⚠️" if sev == "CRITICAL" else "ℹ️"
    return (
        f'<div class="vuln-alert" style="background:{s["bg"]};border-color:{s["border"]};">'
        f'<span class="vuln-icon">{icon}</span>'
        f'<div>'
        f'<span class="vuln-sev" style="color:{s["color"]};">{sev}</span>'
        f'<span class="vuln-title" style="color:{s["color"]};">{v.get("title","")}</span>'
        f'<span class="vuln-desc">{v.get("description","")}</span>'
        f'</div></div>'
    )
