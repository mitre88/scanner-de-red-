"""
Host discovery module for network scanning.

Implements ICMP ping sweep and TCP-based host discovery
for determining which hosts are alive on a network.
"""

import socket
import struct
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Tuple
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class HostStatus:
    """
    Represents the status of a discovered host.

    Attributes:
        ip: IP address of the host
        is_alive: Whether the host responded
        rtt: Round-trip time in milliseconds (if applicable)
        method: Discovery method used (icmp, tcp)
        timestamp: When the discovery was performed
    """
    ip: str
    is_alive: bool
    rtt: Optional[float] = None
    method: str = "unknown"
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class HostDiscovery:
    """
    Handles host discovery using multiple techniques.

    Supports ICMP ping (when permissions allow) and TCP-based
    discovery as a fallback method.
    """

    def __init__(
        self,
        timeout: float = 2.0,
        workers: int = 50,
        tcp_ports: Optional[List[int]] = None
    ):
        """
        Initialize host discovery.

        Args:
            timeout: Timeout for each probe in seconds
            workers: Number of concurrent workers
            tcp_ports: List of TCP ports to try for TCP-based discovery
        """
        self.timeout = timeout
        self.workers = workers
        self.tcp_ports = tcp_ports or [80, 443, 22, 21, 25]

    def discover_hosts(
        self,
        targets: List[str],
        method: str = "auto"
    ) -> List[HostStatus]:
        """
        Discover alive hosts from a list of targets.

        Args:
            targets: List of IP addresses to check
            method: Discovery method - "auto", "icmp", "tcp"

        Returns:
            List of HostStatus objects
        """
        if method == "auto":
            # Try ICMP first, fall back to TCP if needed
            if self._can_use_icmp():
                logger.info("Using ICMP ping for host discovery")
                return self._discover_icmp(targets)
            else:
                logger.info("ICMP not available, using TCP-based discovery")
                return self._discover_tcp(targets)
        elif method == "icmp":
            return self._discover_icmp(targets)
        elif method == "tcp":
            return self._discover_tcp(targets)
        else:
            raise ValueError(f"Unknown discovery method: {method}")

    def _can_use_icmp(self) -> bool:
        """
        Check if ICMP raw sockets are available.

        Returns:
            True if ICMP can be used, False otherwise
        """
        try:
            # Try to create a raw socket
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP
            )
            sock.close()
            return True
        except (PermissionError, OSError):
            return False

    def _discover_icmp(self, targets: List[str]) -> List[HostStatus]:
        """
        Discover hosts using ICMP ping.

        Args:
            targets: List of IP addresses

        Returns:
            List of HostStatus objects
        """
        results = []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_ip = {
                executor.submit(self._ping_host, ip): ip
                for ip in targets
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.debug(f"Error pinging {ip}: {e}")
                    results.append(HostStatus(
                        ip=ip,
                        is_alive=False,
                        method="icmp"
                    ))

        return results

    def _ping_host(self, ip: str) -> HostStatus:
        """
        Ping a single host using ICMP.

        Args:
            ip: IP address to ping

        Returns:
            HostStatus object
        """
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP
            )
            sock.settimeout(self.timeout)

            # Create ICMP echo request
            icmp_id = 12345
            icmp_seq = 1
            packet = self._create_icmp_packet(icmp_id, icmp_seq)

            # Send packet and measure RTT
            start_time = time.time()
            sock.sendto(packet, (ip, 0))

            try:
                # Wait for reply
                data, addr = sock.recvfrom(1024)
                end_time = time.time()
                rtt = (end_time - start_time) * 1000  # Convert to ms

                sock.close()
                return HostStatus(
                    ip=ip,
                    is_alive=True,
                    rtt=rtt,
                    method="icmp"
                )
            except socket.timeout:
                sock.close()
                return HostStatus(
                    ip=ip,
                    is_alive=False,
                    method="icmp"
                )

        except Exception as e:
            logger.debug(f"ICMP ping failed for {ip}: {e}")
            return HostStatus(
                ip=ip,
                is_alive=False,
                method="icmp"
            )

    def _create_icmp_packet(self, icmp_id: int, seq: int) -> bytes:
        """
        Create an ICMP echo request packet.

        Args:
            icmp_id: ICMP identifier
            seq: Sequence number

        Returns:
            Raw packet bytes
        """
        # ICMP Echo Request: type=8, code=0
        icmp_type = 8
        icmp_code = 0
        checksum = 0
        data = b'NetworkScanner'  # Payload

        # Pack header
        header = struct.pack(
            '!BBHHH',
            icmp_type,
            icmp_code,
            checksum,
            icmp_id,
            seq
        )

        # Calculate checksum
        checksum = self._calculate_checksum(header + data)

        # Repack with correct checksum
        header = struct.pack(
            '!BBHHH',
            icmp_type,
            icmp_code,
            checksum,
            icmp_id,
            seq
        )

        return header + data

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Calculate ICMP checksum.

        Args:
            data: Data to checksum

        Returns:
            Checksum value
        """
        if len(data) % 2 == 1:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return ~checksum & 0xffff

    def _discover_tcp(self, targets: List[str]) -> List[HostStatus]:
        """
        Discover hosts using TCP connection attempts.

        Args:
            targets: List of IP addresses

        Returns:
            List of HostStatus objects
        """
        results = []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_ip = {
                executor.submit(self._tcp_probe_host, ip): ip
                for ip in targets
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.debug(f"Error probing {ip}: {e}")
                    results.append(HostStatus(
                        ip=ip,
                        is_alive=False,
                        method="tcp"
                    ))

        return results

    def _tcp_probe_host(self, ip: str) -> HostStatus:
        """
        Probe a host using TCP connection to common ports.

        Args:
            ip: IP address to probe

        Returns:
            HostStatus object
        """
        # Try each port until one connects
        for port in self.tcp_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                start_time = time.time()
                result = sock.connect_ex((ip, port))
                end_time = time.time()

                sock.close()

                if result == 0:
                    # Connection successful
                    rtt = (end_time - start_time) * 1000
                    return HostStatus(
                        ip=ip,
                        is_alive=True,
                        rtt=rtt,
                        method="tcp"
                    )
            except Exception as e:
                logger.debug(f"TCP probe failed for {ip}:{port}: {e}")
                continue

        # No ports responded
        return HostStatus(
            ip=ip,
            is_alive=False,
            method="tcp"
        )
