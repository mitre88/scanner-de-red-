"""
Utility functions for network scanning operations.

This module provides IP address parsing, CIDR range expansion,
port range parsing, and validation utilities.
"""

import ipaddress
import re
from typing import List, Set, Tuple


def parse_targets(target_string: str) -> List[str]:
    """
    Parse target specification into a list of IP addresses.

    Supports:
    - Single IP: "192.168.1.1"
    - Comma-separated IPs: "192.168.1.1,192.168.1.2"
    - CIDR notation: "192.168.1.0/24"
    - Mixed: "192.168.1.1,10.0.0.0/28"

    Args:
        target_string: String containing target specification

    Returns:
        List of IP addresses as strings

    Raises:
        ValueError: If target specification is invalid
    """
    if not target_string or not target_string.strip():
        raise ValueError("Target specification cannot be empty")

    ips: Set[str] = set()

    # Split by comma to handle multiple targets
    targets = [t.strip() for t in target_string.split(',')]

    for target in targets:
        if not target:
            continue

        # Check if it's a CIDR range
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                # Limit to reasonable network sizes (max /16 = 65536 hosts)
                if network.num_addresses > 65536:
                    raise ValueError(
                        f"Network {target} too large (max /16 allowed). "
                        f"Use smaller subnets for safety."
                    )
                ips.update(str(ip) for ip in network.hosts())
            except (ValueError, ipaddress.AddressValueError) as e:
                raise ValueError(f"Invalid CIDR notation '{target}': {e}")
        else:
            # Single IP address
            try:
                # Validate IP address
                ip_obj = ipaddress.ip_address(target)
                ips.add(str(ip_obj))
            except ValueError as e:
                raise ValueError(f"Invalid IP address '{target}': {e}")

    if not ips:
        raise ValueError("No valid IP addresses found in target specification")

    return sorted(ips, key=lambda ip: ipaddress.ip_address(ip))


def parse_port_range(port_string: str) -> List[int]:
    """
    Parse port specification into a list of port numbers.

    Supports:
    - Single port: "80"
    - Comma-separated: "80,443,8080"
    - Ranges: "1-1024"
    - Mixed: "22,80,443,8000-8100"

    Args:
        port_string: String containing port specification

    Returns:
        Sorted list of unique port numbers

    Raises:
        ValueError: If port specification is invalid
    """
    if not port_string or not port_string.strip():
        raise ValueError("Port specification cannot be empty")

    ports: Set[int] = set()

    # Split by comma
    parts = [p.strip() for p in port_string.split(',')]

    for part in parts:
        if not part:
            continue

        # Check if it's a range
        if '-' in part:
            try:
                start_str, end_str = part.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())

                if start < 1 or end > 65535:
                    raise ValueError(
                        f"Port range {part} out of valid range (1-65535)"
                    )
                if start > end:
                    raise ValueError(
                        f"Invalid port range {part}: start > end"
                    )

                # Limit range size for safety
                if end - start > 65535:
                    raise ValueError(
                        f"Port range {part} too large (max 65535 ports)"
                    )

                ports.update(range(start, end + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port range format '{part}'")
                raise
        else:
            # Single port
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number '{part}'")

            if port < 1 or port > 65535:
                raise ValueError(
                    f"Port {port} out of valid range (1-65535)"
                )
            ports.add(port)

    if not ports:
        raise ValueError("No valid ports found in specification")

    return sorted(ports)


def get_common_ports() -> List[int]:
    """
    Return a list of commonly used ports for quick scanning.

    Returns:
        List of common port numbers
    """
    return [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        9200,  # Elasticsearch
        27017, # MongoDB
    ]


def get_common_udp_ports() -> List[int]:
    """
    Return a list of commonly used UDP ports.

    Returns:
        List of common UDP port numbers
    """
    return [
        53,    # DNS
        67,    # DHCP Server
        68,    # DHCP Client
        123,   # NTP
        161,   # SNMP
        162,   # SNMP Trap
        514,   # Syslog
        1900,  # SSDP
    ]


def validate_timeout(timeout: float) -> float:
    """
    Validate and return timeout value.

    Args:
        timeout: Timeout value in seconds

    Returns:
        Validated timeout value

    Raises:
        ValueError: If timeout is invalid
    """
    if timeout <= 0:
        raise ValueError("Timeout must be positive")
    if timeout > 300:  # 5 minutes max
        raise ValueError("Timeout too large (max 300 seconds)")
    return timeout


def validate_workers(workers: int) -> int:
    """
    Validate and return number of concurrent workers.

    Args:
        workers: Number of concurrent workers

    Returns:
        Validated worker count

    Raises:
        ValueError: If worker count is invalid
    """
    if workers < 1:
        raise ValueError("Worker count must be at least 1")
    if workers > 1000:
        raise ValueError("Worker count too large (max 1000)")
    return workers


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.2f}s"
