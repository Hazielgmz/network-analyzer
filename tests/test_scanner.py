"""
Unit tests for the scanner modules.

Run with:
    python -m pytest tests/ -v
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner.port_scanner import COMMON_PORTS, scan_ports
from scanner.vuln_checker import check_vulnerabilities, severity_summary


# ---------------------------------------------------------------------------
# port_scanner
# ---------------------------------------------------------------------------

class TestScanPorts:
    def test_returns_list(self):
        with patch("scanner.port_scanner._check_port", return_value=None):
            result = scan_ports("127.0.0.1", ports=[80, 443])
        assert isinstance(result, list)

    def test_open_port_included(self):
        fake_port = {"port": 80, "state": "open", "service": "HTTP"}
        with patch("scanner.port_scanner._check_port", return_value=fake_port):
            result = scan_ports("127.0.0.1", ports=[80])
        assert len(result) == 1
        assert result[0]["port"] == 80

    def test_closed_port_excluded(self):
        with patch("scanner.port_scanner._check_port", return_value=None):
            result = scan_ports("127.0.0.1", ports=[9999])
        assert result == []

    def test_results_sorted_by_port(self):
        def fake_check(ip, port, timeout):
            return {"port": port, "state": "open", "service": "X"}

        with patch("scanner.port_scanner._check_port", side_effect=fake_check):
            result = scan_ports("127.0.0.1", ports=[443, 22, 80])

        ports = [r["port"] for r in result]
        assert ports == sorted(ports)

    def test_default_ports_used_when_none_provided(self):
        with patch("scanner.port_scanner._check_port", return_value=None):
            scan_ports("127.0.0.1")

    def test_localhost_port_80(self):
        """Integration-style: tries real connection to localhost:80 (expected closed/refused)."""
        result = scan_ports("127.0.0.1", ports=[80], timeout=0.2)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# vuln_checker
# ---------------------------------------------------------------------------

class TestCheckVulnerabilities:
    def _make_port(self, port: int, service: str = "X") -> dict:
        return {"port": port, "state": "open", "service": service}

    def test_empty_input_returns_empty(self):
        assert check_vulnerabilities([]) == []

    def test_detects_telnet(self):
        findings = check_vulnerabilities([self._make_port(23, "Telnet")])
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_detects_ftp(self):
        findings = check_vulnerabilities([self._make_port(21, "FTP")])
        assert findings[0]["severity"] == "HIGH"

    def test_unknown_port_ignored(self):
        findings = check_vulnerabilities([self._make_port(9999, "unknown")])
        assert findings == []

    def test_sorted_by_severity(self):
        ports = [
            self._make_port(80, "HTTP"),    # LOW
            self._make_port(21, "FTP"),     # HIGH
            self._make_port(23, "Telnet"),  # CRITICAL
        ]
        findings = check_vulnerabilities(ports)
        severities = [f["severity"] for f in findings]
        assert severities == ["CRITICAL", "HIGH", "LOW"]

    def test_finding_has_required_keys(self):
        findings = check_vulnerabilities([self._make_port(23, "Telnet")])
        for key in ("port", "service", "severity", "title", "description"):
            assert key in findings[0]


class TestSeveritySummary:
    def test_empty_findings(self):
        summary = severity_summary([])
        assert summary == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def test_counts_correctly(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "LOW"},
        ]
        summary = severity_summary(findings)
        assert summary["CRITICAL"] == 1
        assert summary["HIGH"] == 2
        assert summary["MEDIUM"] == 0
        assert summary["LOW"] == 1
