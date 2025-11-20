"""
Unit tests for host discovery module.
"""

import pytest
from scanner.discovery import HostDiscovery, HostStatus


class TestHostStatus:
    """Tests for HostStatus dataclass."""

    def test_creation(self):
        """Test creating HostStatus instance."""
        status = HostStatus(
            ip="192.168.1.1",
            is_alive=True,
            rtt=15.5,
            method="icmp"
        )

        assert status.ip == "192.168.1.1"
        assert status.is_alive is True
        assert status.rtt == 15.5
        assert status.method == "icmp"
        assert status.timestamp is not None

    def test_default_timestamp(self):
        """Test that timestamp is set automatically."""
        status = HostStatus(ip="192.168.1.1", is_alive=False)
        assert status.timestamp is not None


class TestHostDiscovery:
    """Tests for HostDiscovery class."""

    def test_initialization(self):
        """Test HostDiscovery initialization."""
        discovery = HostDiscovery(timeout=3.0, workers=25)
        assert discovery.timeout == 3.0
        assert discovery.workers == 25

    def test_default_tcp_ports(self):
        """Test that default TCP ports are set."""
        discovery = HostDiscovery()
        assert discovery.tcp_ports is not None
        assert len(discovery.tcp_ports) > 0
        assert 80 in discovery.tcp_ports
        assert 443 in discovery.tcp_ports

    def test_custom_tcp_ports(self):
        """Test setting custom TCP ports."""
        discovery = HostDiscovery(tcp_ports=[8080, 8443])
        assert discovery.tcp_ports == [8080, 8443]

    def test_can_use_icmp_detection(self):
        """Test ICMP capability detection."""
        discovery = HostDiscovery()
        result = discovery._can_use_icmp()
        # Result depends on privileges, just check it's boolean
        assert isinstance(result, bool)

    def test_discover_hosts_method_validation(self):
        """Test that invalid method raises error."""
        discovery = HostDiscovery()
        with pytest.raises(ValueError, match="Unknown discovery method"):
            discovery.discover_hosts(["192.168.1.1"], method="invalid")

    def test_tcp_probe_localhost(self):
        """Test TCP probe against localhost (should fail or succeed based on ports)."""
        discovery = HostDiscovery(timeout=0.5, tcp_ports=[22, 80])
        # This test doesn't assert success/failure since it depends on environment
        # Just ensure it doesn't crash
        result = discovery._tcp_probe_host("127.0.0.1")
        assert isinstance(result, HostStatus)
        assert result.ip == "127.0.0.1"
        assert result.method == "tcp"
