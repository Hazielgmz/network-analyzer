VULNERABILITY_RULES: list[dict] = [
    {
        "port": 23,
        "service": "Telnet",
        "severity": "CRITICAL",
        "title": "Telnet expuesto",
        "description": (
            "Telnet transmite credenciales y datos en texto plano. "
            "Cualquier atacante en la red puede interceptar la sesión. "
            "Deshabilita el servicio y usa SSH en su lugar."
        ),
    },
    {
        "port": 21,
        "service": "FTP",
        "severity": "HIGH",
        "title": "FTP sin cifrado",
        "description": (
            "FTP no cifra la transferencia de archivos ni las credenciales. "
            "Considera usar SFTP o FTPS."
        ),
    },
    {
        "port": 445,
        "service": "SMB",
        "severity": "HIGH",
        "title": "SMB expuesto",
        "description": (
            "El protocolo SMB ha sido vector de ataques críticos (EternalBlue/WannaCry). "
            "Asegúrate de tener los parches de seguridad aplicados y restringe el acceso."
        ),
    },
    {
        "port": 3389,
        "service": "RDP",
        "severity": "HIGH",
        "title": "RDP expuesto",
        "description": (
            "Remote Desktop Protocol accesible desde la red. "
            "Limita el acceso con VPN o firewall y habilita autenticación a nivel de red (NLA)."
        ),
    },
    {
        "port": 5900,
        "service": "VNC",
        "severity": "HIGH",
        "title": "VNC expuesto",
        "description": (
            "VNC puede estar configurado sin contraseña o con contraseña débil. "
            "Restringe el acceso por firewall o usa un túnel SSH."
        ),
    },
    {
        "port": 3306,
        "service": "MySQL",
        "severity": "MEDIUM",
        "title": "Base de datos MySQL accesible",
        "description": (
            "MySQL escucha en la red. Si no es necesario, restringe a localhost (127.0.0.1). "
            "Revisa los usuarios y privilegios configurados."
        ),
    },
    {
        "port": 111,
        "service": "RPCbind",
        "severity": "MEDIUM",
        "title": "RPCbind expuesto",
        "description": (
            "RPCbind puede revelar información sobre servicios RPC activos "
            "y ha sido explotado en ataques de amplificación UDP."
        ),
    },
    {
        "port": 135,
        "service": "MS RPC",
        "severity": "MEDIUM",
        "title": "MS RPC expuesto",
        "description": (
            "Microsoft RPC expuesto puede ser aprovechado para movimiento lateral "
            "en redes Windows. Restringe con firewall."
        ),
    },
    {
        "port": 139,
        "service": "NetBIOS",
        "severity": "MEDIUM",
        "title": "NetBIOS expuesto",
        "description": (
            "NetBIOS puede filtrar el nombre del equipo y comparticiones de red. "
            "Deshabilítalo si no es necesario."
        ),
    },
    {
        "port": 1723,
        "service": "PPTP",
        "severity": "MEDIUM",
        "title": "VPN PPTP en uso",
        "description": (
            "PPTP tiene vulnerabilidades criptográficas conocidas (MS-CHAPv2). "
            "Migra a IKEv2/IPSec u OpenVPN."
        ),
    },
    {
        "port": 80,
        "service": "HTTP",
        "severity": "LOW",
        "title": "HTTP sin TLS",
        "description": (
            "El servidor web responde en HTTP plano. "
            "Configura HTTPS con un certificado válido para proteger la comunicación."
        ),
    },
    {
        "port": 8080,
        "service": "HTTP-Alt",
        "severity": "LOW",
        "title": "Puerto HTTP alternativo abierto",
        "description": (
            "Un servidor web corre en el puerto 8080. "
            "Verifica que no sea una aplicación de administración expuesta sin autenticación."
        ),
    },
    {
        "port": 8888,
        "service": "HTTP-Dev",
        "severity": "LOW",
        "title": "Posible servidor de desarrollo expuesto",
        "description": (
            "El puerto 8888 es común en servidores de desarrollo (Jupyter, etc.). "
            "No debe estar expuesto en producción o en redes no confiables."
        ),
    },
]

_RULES_BY_PORT: dict[int, dict] = {rule["port"]: rule for rule in VULNERABILITY_RULES}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def check_vulnerabilities(scan_results: list[dict]) -> list[dict]:
    """
    Compara los puertos abiertos contra las reglas de vulnerabilidad conocidas.

    Args:
        scan_results: salida de port_scanner.scan_ports()
                      ej. [{"port": 23, "state": "open", "service": "Telnet"}]

    Returns:
        Lista de vulnerabilidades ordenadas por severidad (CRITICAL primero).
    """
    findings = []
    for port_info in scan_results:
        port = port_info.get("port")
        rule = _RULES_BY_PORT.get(port)
        if rule:
            findings.append({
                "port": port,
                "service": rule["service"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
            })

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def severity_summary(findings: list[dict]) -> dict[str, int]:
    """Devuelve el conteo de hallazgos por nivel de severidad para el dashboard."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        level = f.get("severity", "LOW")
        if level in summary:
            summary[level] += 1
    return summary
