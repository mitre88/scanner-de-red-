"""
Unit tests for utility functions.
"""

import pytest
from scanner.utils import (
    parse_targets,
    parse_port_range,
    get_common_ports,
    get_common_udp_ports,
    validate_timeout,
    validate_workers,
    format_duration
)


class TestParseTargets:
    """Tests for parse_targets function."""

    def test_single_ip(self):
        """Test parsing a single IP address."""
        result = parse_targets("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_multiple_ips(self):
        """Test parsing comma-separated IPs."""
        result = parse_targets("192.168.1.1,192.168.1.2,192.168.1.3")
        assert len(result) == 3
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "192.168.1.3" in result

    def test_cidr_notation_small(self):
        """Test parsing small CIDR range."""
        result = parse_targets("192.168.1.0/30")
        # /30 should give 2 usable hosts
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_cidr_notation_slash24(self):
        """Test parsing /24 CIDR range."""
        result = parse_targets("10.0.0.0/24")
        # /24 should give 254 usable hosts
        assert len(result) == 254
        assert "10.0.0.1" in result
        assert "10.0.0.254" in result

    def test_mixed_targets(self):
        """Test parsing mixed IP and CIDR."""
        result = parse_targets("192.168.1.1,10.0.0.0/30")
        assert len(result) == 3  # 1 IP + 2 from /30
        assert "192.168.1.1" in result

    def test_invalid_ip(self):
        """Test that invalid IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            parse_targets("999.999.999.999")

    def test_invalid_cidr(self):
        """Test that invalid CIDR raises ValueError."""
        with pytest.raises(ValueError, match="Invalid CIDR notation"):
            parse_targets("192.168.1.0/99")

    def test_empty_string(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_targets("")

    def test_too_large_network(self):
        """Test that very large networks are rejected."""
        with pytest.raises(ValueError, match="too large"):
            parse_targets("10.0.0.0/8")


class TestParsePortRange:
    """Tests for parse_port_range function."""

    def test_single_port(self):
        """Test parsing a single port."""
        result = parse_port_range("80")
        assert result == [80]

    def test_multiple_ports(self):
        """Test parsing comma-separated ports."""
        result = parse_port_range("22,80,443")
        assert result == [22, 80, 443]

    def test_port_range(self):
        """Test parsing port range."""
        result = parse_port_range("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed_format(self):
        """Test parsing mixed ports and ranges."""
        result = parse_port_range("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_invalid_port_too_high(self):
        """Test that port > 65535 raises ValueError."""
        with pytest.raises(ValueError, match="out of valid range"):
            parse_port_range("70000")

    def test_invalid_port_zero(self):
        """Test that port 0 raises ValueError."""
        with pytest.raises(ValueError, match="out of valid range"):
            parse_port_range("0")

    def test_invalid_range(self):
        """Test that invalid range raises ValueError."""
        with pytest.raises(ValueError, match="Invalid port range format"):
            parse_port_range("abc-def")

    def test_reversed_range(self):
        """Test that reversed range raises ValueError."""
        with pytest.raises(ValueError, match="start > end"):
            parse_port_range("100-50")

    def test_empty_string(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_port_range("")


class TestGetCommonPorts:
    """Tests for get_common_ports function."""

    def test_returns_list(self):
        """Test that function returns a list."""
        result = get_common_ports()
        assert isinstance(result, list)

    def test_contains_common_ports(self):
        """Test that result contains expected common ports."""
        result = get_common_ports()
        assert 22 in result  # SSH
        assert 80 in result  # HTTP
        assert 443 in result  # HTTPS

    def test_all_valid_ports(self):
        """Test that all returned ports are valid."""
        result = get_common_ports()
        assert all(1 <= p <= 65535 for p in result)


class TestGetCommonUdpPorts:
    """Tests for get_common_udp_ports function."""

    def test_returns_list(self):
        """Test that function returns a list."""
        result = get_common_udp_ports()
        assert isinstance(result, list)

    def test_contains_dns(self):
        """Test that result contains DNS port."""
        result = get_common_udp_ports()
        assert 53 in result

    def test_all_valid_ports(self):
        """Test that all returned ports are valid."""
        result = get_common_udp_ports()
        assert all(1 <= p <= 65535 for p in result)


class TestValidateTimeout:
    """Tests for validate_timeout function."""

    def test_valid_timeout(self):
        """Test that valid timeout is accepted."""
        result = validate_timeout(2.0)
        assert result == 2.0

    def test_zero_timeout(self):
        """Test that zero timeout raises ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            validate_timeout(0)

    def test_negative_timeout(self):
        """Test that negative timeout raises ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            validate_timeout(-1)

    def test_too_large_timeout(self):
        """Test that very large timeout raises ValueError."""
        with pytest.raises(ValueError, match="too large"):
            validate_timeout(500)


class TestValidateWorkers:
    """Tests for validate_workers function."""

    def test_valid_workers(self):
        """Test that valid worker count is accepted."""
        result = validate_workers(100)
        assert result == 100

    def test_zero_workers(self):
        """Test that zero workers raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            validate_workers(0)

    def test_negative_workers(self):
        """Test that negative workers raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            validate_workers(-1)

    def test_too_many_workers(self):
        """Test that excessive workers raises ValueError."""
        with pytest.raises(ValueError, match="too large"):
            validate_workers(2000)


class TestFormatDuration:
    """Tests for format_duration function."""

    def test_seconds_only(self):
        """Test formatting seconds."""
        result = format_duration(45.5)
        assert "45.50s" in result

    def test_minutes(self):
        """Test formatting minutes."""
        result = format_duration(125)
        assert "2m" in result
        assert "5.00s" in result

    def test_hours(self):
        """Test formatting hours."""
        result = format_duration(7325)
        assert "2h" in result
        assert "2m" in result
