import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888,
]

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
}


def scan_ports(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 0.5,
    max_workers: int = 100,
) -> list[dict]:
    """
    Escaneo TCP connect contra una IP individual.

    Args:
        ip: dirección IP objetivo
        ports: lista de puertos a escanear; usa COMMON_PORTS por defecto
        timeout: segundos de espera por intento de conexión
        max_workers: hilos paralelos

    Returns:
        Lista de puertos abiertos: [{"port": int, "state": "open", "service": str}]
    """
    targets = ports if ports is not None else COMMON_PORTS
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_port, ip, port, timeout): port for port in targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda p: p["port"])
    return open_ports


def _check_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as _:
            service = SERVICE_NAMES.get(port) or _probe_banner(ip, port, timeout)
            return {"port": port, "state": "open", "service": service}
    except (ConnectionRefusedError, TimeoutError, OSError):
        return None


def _probe_banner(ip: str, port: int, timeout: float) -> str:
    """Intenta capturar el banner del servicio para identificar puertos desconocidos."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(256).decode(errors="ignore").strip()
            if banner:
                return banner.splitlines()[0][:40]
    except OSError:
        pass
    return "unknown"
