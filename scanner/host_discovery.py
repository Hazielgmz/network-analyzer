import socket
import logging
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from mac_vendor_lookup import MacLookup, VendorNotFoundError

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

_mac_lookup = MacLookup()


def discover_hosts(network: str, timeout: int = 2) -> list[dict]:
    """
    Envía un broadcast ARP a la red CIDR indicada y devuelve
    una lista de hosts activos con su IP, MAC, hostname y fabricante.

    Requiere permisos de root/administrador para enviar paquetes raw.

    Args:
        network: notación CIDR, ej. "192.168.1.0/24"
        timeout: segundos de espera para las respuestas ARP

    Returns:
        Lista de dicts: [{"ip": str, "mac": str, "hostname": str, "vendor": str}]
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(packet, timeout=timeout, verbose=False)

    hosts = []
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        hostname = _resolve_hostname(ip)
        vendor = _lookup_vendor(mac)
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})

    hosts.sort(key=lambda h: _ip_sort_key(h["ip"]))
    return hosts


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "unknown"


def _lookup_vendor(mac: str) -> str:
    try:
        return _mac_lookup.lookup(mac)
    except (VendorNotFoundError, KeyError, ValueError):
        return "unknown"


def _ip_sort_key(ip: str) -> tuple:
    return tuple(int(part) for part in ip.split("."))
