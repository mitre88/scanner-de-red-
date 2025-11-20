"""
Unit tests for port scanner module.
"""

import pytest
from scanner.scanner import PortScanner, PortResult, ScanResult, PortState


class TestPortResult:
    """Tests for PortResult dataclass."""

    def test_creation(self):
        """Test creating PortResult instance."""
        result = PortResult(
            port=80,
            protocol="tcp",
            state=PortState.OPEN,
            service="http"
        )

        assert result.port == 80
        assert result.protocol == "tcp"
        assert result.state == PortState.OPEN
        assert result.service == "http"
        assert result.timestamp is not None


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_creation(self):
        """Test creating ScanResult instance."""
        ports = [
            PortResult(80, "tcp", PortState.OPEN, "http"),
            PortResult(443, "tcp", PortState.OPEN, "https"),
            PortResult(8080, "tcp", PortState.CLOSED)
        ]

        result = ScanResult(
            ip="192.168.1.1",
            ports=ports,
            scan_duration=5.5
        )

        assert result.ip == "192.168.1.1"
        assert len(result.ports) == 3
        assert result.scan_duration == 5.5
        assert result.timestamp is not None

    def test_get_open_ports(self):
        """Test getting only open ports."""
        ports = [
            PortResult(80, "tcp", PortState.OPEN, "http"),
            PortResult(443, "tcp", PortState.OPEN, "https"),
            PortResult(8080, "tcp", PortState.CLOSED)
        ]

        result = ScanResult("192.168.1.1", ports, 1.0)
        open_ports = result.get_open_ports()

        assert len(open_ports) == 2
        assert all(p.state == PortState.OPEN for p in open_ports)


class TestPortScanner:
    """Tests for PortScanner class."""

    def test_initialization(self):
        """Test PortScanner initialization."""
        scanner = PortScanner(timeout=2.0, workers=50)
        assert scanner.timeout == 2.0
        assert scanner.workers == 50

    def test_common_services_mapping(self):
        """Test that common services are mapped."""
        assert PortScanner.COMMON_SERVICES[22] == "ssh"
        assert PortScanner.COMMON_SERVICES[80] == "http"
        assert PortScanner.COMMON_SERVICES[443] == "https"

    def test_scan_tcp_ports_returns_result(self):
        """Test that TCP scan returns ScanResult."""
        scanner = PortScanner(timeout=0.5)
        # Scan localhost on a port that's likely closed
        result = scanner.scan_tcp_ports("127.0.0.1", [9999])

        assert isinstance(result, ScanResult)
        assert result.ip == "127.0.0.1"
        assert isinstance(result.ports, list)
        assert result.scan_duration >= 0

    def test_scan_udp_ports_returns_result(self):
        """Test that UDP scan returns ScanResult."""
        scanner = PortScanner(timeout=0.5)
        result = scanner.scan_udp_ports("127.0.0.1", [9999])

        assert isinstance(result, ScanResult)
        assert result.ip == "127.0.0.1"
        assert isinstance(result.ports, list)

    def test_scan_host_both_protocols(self):
        """Test scanning both TCP and UDP."""
        scanner = PortScanner(timeout=0.5)
        result = scanner.scan_host(
            "127.0.0.1",
            tcp_ports=[9999],
            udp_ports=[9999]
        )

        assert 'tcp' in result
        assert 'udp' in result
        assert isinstance(result['tcp'], ScanResult)
        assert isinstance(result['udp'], ScanResult)

    def test_get_udp_probe_dns(self):
        """Test getting DNS UDP probe."""
        scanner = PortScanner()
        probe = scanner._get_udp_probe(53)
        assert isinstance(probe, bytes)
        assert len(probe) > 0

    def test_get_udp_probe_default(self):
        """Test getting default UDP probe."""
        scanner = PortScanner()
        probe = scanner._get_udp_probe(9999)
        assert isinstance(probe, bytes)
