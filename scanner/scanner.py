"""
Port scanning module for network scanning.

Implements TCP connect scanning and basic UDP scanning
for port enumeration and service discovery.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from enum import Enum


logger = logging.getLogger(__name__)


class PortState(Enum):
    """Enumeration of possible port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"  # Mainly for UDP


@dataclass
class PortResult:
    """
    Represents the result of scanning a single port.

    Attributes:
        port: Port number
        protocol: Protocol (tcp or udp)
        state: Port state
        service: Service name (if known)
        timestamp: When the scan was performed
    """
    port: int
    protocol: str
    state: PortState
    service: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class ScanResult:
    """
    Represents the complete scan result for a host.

    Attributes:
        ip: Target IP address
        ports: List of PortResult objects
        scan_duration: Time taken for the scan in seconds
        timestamp: When the scan started
    """
    ip: str
    ports: List[PortResult]
    scan_duration: float
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

    def get_open_ports(self) -> List[PortResult]:
        """Get only open ports."""
        return [p for p in self.ports if p.state == PortState.OPEN]


class PortScanner:
    """
    Handles TCP and UDP port scanning operations.

    Implements TCP connect scanning (no SYN scanning to avoid
    requiring root privileges) and basic UDP probing.
    """

    # Common service name mappings
    COMMON_SERVICES = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }

    def __init__(
        self,
        timeout: float = 1.0,
        workers: int = 100
    ):
        """
        Initialize port scanner.

        Args:
            timeout: Connection timeout in seconds
            workers: Number of concurrent workers
        """
        self.timeout = timeout
        self.workers = workers

    def scan_tcp_ports(
        self,
        ip: str,
        ports: List[int]
    ) -> ScanResult:
        """
        Scan TCP ports on a target host.

        Args:
            ip: Target IP address
            ports: List of port numbers to scan

        Returns:
            ScanResult object
        """
        start_time = datetime.now()
        results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_port = {
                executor.submit(self._scan_tcp_port, ip, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:  # Only include if not None
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Error scanning TCP {ip}:{port}: {e}")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            ip=ip,
            ports=sorted(results, key=lambda x: x.port),
            scan_duration=duration,
            timestamp=start_time
        )

    def _scan_tcp_port(
        self,
        ip: str,
        port: int
    ) -> Optional[PortResult]:
        """
        Scan a single TCP port.

        Args:
            ip: Target IP address
            port: Port number

        Returns:
            PortResult object or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                # Port is open
                service = self.COMMON_SERVICES.get(port)
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service=service
                )
            else:
                # Port is closed/filtered
                # We typically don't report closed ports to reduce noise
                return None

        except socket.timeout:
            # Likely filtered
            return None
        except Exception as e:
            logger.debug(f"Error scanning TCP {ip}:{port}: {e}")
            return None

    def scan_udp_ports(
        self,
        ip: str,
        ports: List[int]
    ) -> ScanResult:
        """
        Scan UDP ports on a target host.

        Note: UDP scanning is inherently unreliable. We send a UDP packet
        and listen for ICMP port unreachable. No response may mean open
        or filtered.

        Args:
            ip: Target IP address
            ports: List of port numbers to scan

        Returns:
            ScanResult object
        """
        start_time = datetime.now()
        results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_port = {
                executor.submit(self._scan_udp_port, ip, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Error scanning UDP {ip}:{port}: {e}")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            ip=ip,
            ports=sorted(results, key=lambda x: x.port),
            scan_duration=duration,
            timestamp=start_time
        )

    def _scan_udp_port(
        self,
        ip: str,
        port: int
    ) -> Optional[PortResult]:
        """
        Scan a single UDP port.

        UDP scanning limitations:
        - If we get ICMP port unreachable -> closed
        - If we get a UDP response -> open
        - If we get no response -> open|filtered (can't distinguish)

        Args:
            ip: Target IP address
            port: Port number

        Returns:
            PortResult object or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send empty UDP packet (or protocol-specific if known)
            probe_data = self._get_udp_probe(port)
            sock.sendto(probe_data, (ip, port))

            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()

                # Got a response - port is open
                service = self.COMMON_SERVICES.get(port)
                return PortResult(
                    port=port,
                    protocol="udp",
                    state=PortState.OPEN,
                    service=service
                )

            except socket.timeout:
                # No response - could be open or filtered
                # We'll report it as open|filtered
                service = self.COMMON_SERVICES.get(port)
                return PortResult(
                    port=port,
                    protocol="udp",
                    state=PortState.OPEN_FILTERED,
                    service=service
                )

        except ConnectionRefusedError:
            # ICMP port unreachable received - port is closed
            # We typically don't report closed ports
            return None
        except Exception as e:
            logger.debug(f"Error scanning UDP {ip}:{port}: {e}")
            return None

    def _get_udp_probe(self, port: int) -> bytes:
        """
        Get appropriate UDP probe packet for known services.

        Args:
            port: Port number

        Returns:
            Probe packet as bytes
        """
        # For DNS
        if port == 53:
            # DNS query for version.bind (simplified)
            return b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        # For SNMP
        elif port == 161:
            # SNMPv1 Get Request (simplified)
            return b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63'

        # Default empty probe
        else:
            return b''

    def scan_host(
        self,
        ip: str,
        tcp_ports: Optional[List[int]] = None,
        udp_ports: Optional[List[int]] = None
    ) -> Dict[str, ScanResult]:
        """
        Scan both TCP and UDP ports on a host.

        Args:
            ip: Target IP address
            tcp_ports: List of TCP ports to scan
            udp_ports: List of UDP ports to scan

        Returns:
            Dictionary with 'tcp' and 'udp' ScanResult objects
        """
        results = {}

        if tcp_ports:
            results['tcp'] = self.scan_tcp_ports(ip, tcp_ports)

        if udp_ports:
            results['udp'] = self.scan_udp_ports(ip, udp_ports)

        return results
