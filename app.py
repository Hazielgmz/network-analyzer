import os
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file

from reports.generator import save_html, save_json, to_html
from scanner.host_discovery import discover_hosts
from scanner.port_scanner import scan_ports
from scanner.vuln_checker import check_vulnerabilities, severity_summary

app = Flask(__name__)

_last_report_path: str | None = None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Runs a full network scan pipeline.

    Expected JSON body: {"network": "192.168.1.0/24"}

    Returns JSON with discovered hosts, open ports, vulnerabilities, and summary.
    """
    global _last_report_path

    data = request.get_json(silent=True) or {}
    network = data.get("network", "").strip()

    if not network:
        return jsonify({"error": "El campo 'network' es requerido (ej: 192.168.1.0/24)"}), 400

    try:
        hosts = discover_hosts(network)
    except PermissionError:
        return jsonify({"error": "Se requieren permisos de administrador para el escaneo ARP."}), 403
    except Exception as exc:
        return jsonify({"error": f"Error al descubrir hosts: {str(exc)}"}), 500

    enriched_hosts = []
    all_vulns = []

    for host in hosts:
        try:
            ports = scan_ports(host["ip"])
        except Exception:
            ports = []

        vulns = check_vulnerabilities(ports)
        all_vulns.extend(vulns)

        enriched_hosts.append({
            **host,
            "ports": ports,
            "vulnerabilities": vulns,
        })

    summary = severity_summary(all_vulns)

    results = {
        "network": network,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_hosts": len(enriched_hosts),
        "summary": summary,
        "hosts": enriched_hosts,
    }

    try:
        _last_report_path = save_html(results)
        save_json(results)
    except Exception:
        pass

    return jsonify(results)


@app.route("/report/download")
def download_report():
    """Downloads the last generated HTML report."""
    if not _last_report_path or not os.path.exists(_last_report_path):
        return jsonify({"error": "No hay reporte disponible. Realiza un escaneo primero."}), 404
    return send_file(_last_report_path, as_attachment=True, download_name="network_report.html")


@app.route("/report/preview")
def preview_report():
    """Renders the last HTML report inline in the browser."""
    if not _last_report_path or not os.path.exists(_last_report_path):
        return jsonify({"error": "No hay reporte disponible. Realiza un escaneo primero."}), 404
    with open(_last_report_path, encoding="utf-8") as f:
        return f.read()
