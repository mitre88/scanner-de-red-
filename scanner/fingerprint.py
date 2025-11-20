"""
OS fingerprinting module for network scanning.

Implements basic, best-effort OS detection using TCP/IP
stack characteristics like TTL values, TCP window sizes,
and other observable behaviors.

Note: This is a simplified approach and should be considered
low-confidence without extensive signature databases.
"""

import socket
import struct
import logging
from dataclasses import dataclass
from typing import Optional, Dict, List
from enum import Enum


logger = logging.getLogger(__name__)


class OSFamily(Enum):
    """Enumeration of OS families."""
    LINUX = "Linux"
    WINDOWS = "Windows"
    BSD = "BSD"
    MACOS = "macOS"
    UNIX = "Unix"
    NETWORK_DEVICE = "Network Device"
    UNKNOWN = "Unknown"


@dataclass
class OSFingerprint:
    """
    Results of OS fingerprinting.

    Attributes:
        os_family: Detected OS family
        confidence: Confidence level (0.0-1.0)
        details: Additional details about the detection
        ttl: TTL value observed
        window_size: TCP window size observed
        characteristics: Other observed characteristics
    """
    os_family: OSFamily
    confidence: float
    details: Optional[str] = None
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    characteristics: Optional[Dict[str, str]] = None


class OSFingerprinter:
    """
    Performs basic OS fingerprinting using passive techniques.

    Uses observable TCP/IP stack characteristics to make
    best-effort OS identification.
    """

    # TTL-based OS guessing (initial TTL values)
    # Most systems decrement TTL, so we look for common starting values
    TTL_SIGNATURES = {
        64: OSFamily.LINUX,      # Linux, Unix
        128: OSFamily.WINDOWS,   # Windows
        255: OSFamily.UNIX,      # Some Unix, network devices
        32: OSFamily.WINDOWS,    # Old Windows
    }

    # Window size patterns (common defaults)
    WINDOW_SIGNATURES = {
        5840: OSFamily.LINUX,
        8192: OSFamily.WINDOWS,
        65535: OSFamily.BSD,
        16384: OSFamily.MACOS,
    }

    def __init__(self, timeout: float = 2.0):
        """
        Initialize OS fingerprinter.

        Args:
            timeout: Timeout for probes in seconds
        """
        self.timeout = timeout

    def fingerprint(
        self,
        ip: str,
        open_ports: Optional[List[int]] = None
    ) -> OSFingerprint:
        """
        Perform OS fingerprinting on a target.

        Args:
            ip: Target IP address
            open_ports: List of known open ports (helps with probing)

        Returns:
            OSFingerprint object
        """
        # Collect various characteristics
        ttl = self._probe_ttl(ip, open_ports)
        window_size = self._probe_window_size(ip, open_ports)

        # Analyze collected data
        os_family, confidence, details = self._analyze_fingerprint(
            ttl, window_size
        )

        characteristics = {}
        if ttl:
            characteristics['ttl'] = str(ttl)
        if window_size:
            characteristics['window_size'] = str(window_size)

        return OSFingerprint(
            os_family=os_family,
            confidence=confidence,
            details=details,
            ttl=ttl,
            window_size=window_size,
            characteristics=characteristics if characteristics else None
        )

    def _probe_ttl(
        self,
        ip: str,
        open_ports: Optional[List[int]] = None
    ) -> Optional[int]:
        """
        Probe target to determine TTL value.

        We can observe TTL from any response packet. The TTL we see
        is typically the initial TTL minus the number of hops.

        Args:
            ip: Target IP address
            open_ports: List of open ports to probe

        Returns:
            Observed TTL value or None
        """
        # If we have open ports, try those first
        ports_to_try = open_ports[:3] if open_ports else [80, 443, 22]

        for port in ports_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                # Connect to get a response
                result = sock.connect_ex((ip, port))

                if result == 0:
                    # Get socket option for TTL (IP_TTL)
                    # Note: This gets the TTL we're sending, not receiving
                    # For received TTL, we'd need raw sockets
                    sock.close()

                    # Alternative: Use ICMP if available
                    ttl = self._probe_ttl_icmp(ip)
                    if ttl:
                        return ttl

            except Exception as e:
                logger.debug(f"TTL probe failed for {ip}:{port}: {e}")

        # Try ICMP probe
        return self._probe_ttl_icmp(ip)

    def _probe_ttl_icmp(self, ip: str) -> Optional[int]:
        """
        Probe TTL using ICMP echo request.

        Args:
            ip: Target IP address

        Returns:
            TTL value or None
        """
        try:
            # Try to create raw socket for ICMP
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP
            )
            sock.settimeout(self.timeout)

            # Send ICMP echo request
            icmp_id = 12345
            icmp_seq = 1
            packet = self._create_icmp_packet(icmp_id, icmp_seq)

            sock.sendto(packet, (ip, 0))

            # Receive response and extract TTL from IP header
            data, addr = sock.recvfrom(1024)
            sock.close()

            # Extract TTL from IP header (9th byte)
            if len(data) >= 20:
                ttl = data[8]
                # Round up to common initial TTL values
                return self._estimate_initial_ttl(ttl)

        except (PermissionError, OSError) as e:
            logger.debug(f"ICMP TTL probe requires root/admin privileges: {e}")
        except Exception as e:
            logger.debug(f"ICMP TTL probe failed for {ip}: {e}")

        return None

    def _estimate_initial_ttl(self, observed_ttl: int) -> int:
        """
        Estimate the initial TTL value from observed TTL.

        Common initial TTL values: 32, 64, 128, 255

        Args:
            observed_ttl: The TTL value we observed

        Returns:
            Estimated initial TTL
        """
        common_ttls = [32, 64, 128, 255]

        # Find the closest common TTL that's >= observed
        for ttl in common_ttls:
            if ttl >= observed_ttl:
                return ttl

        return 255  # Default to highest

    def _create_icmp_packet(self, icmp_id: int, seq: int) -> bytes:
        """
        Create an ICMP echo request packet.

        Args:
            icmp_id: ICMP identifier
            seq: Sequence number

        Returns:
            Raw packet bytes
        """
        icmp_type = 8  # Echo request
        icmp_code = 0
        checksum = 0
        data = b'OSFingerprint'

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
        """Calculate ICMP checksum."""
        if len(data) % 2 == 1:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return ~checksum & 0xffff

    def _probe_window_size(
        self,
        ip: str,
        open_ports: Optional[List[int]] = None
    ) -> Optional[int]:
        """
        Attempt to determine TCP window size.

        Note: This is difficult without raw sockets to inspect
        the SYN-ACK packet. This is a placeholder implementation.

        Args:
            ip: Target IP address
            open_ports: List of open ports

        Returns:
            Window size or None
        """
        # Window size detection requires analyzing SYN-ACK packets
        # which needs raw socket access. Without that, we can't
        # reliably determine the window size.

        # This is a limitation of our implementation.
        # A full implementation would use scapy or similar.

        logger.debug("Window size detection requires raw socket access")
        return None

    def _analyze_fingerprint(
        self,
        ttl: Optional[int],
        window_size: Optional[int]
    ) -> tuple[OSFamily, float, Optional[str]]:
        """
        Analyze collected fingerprint data to guess OS.

        Args:
            ttl: Observed TTL value
            window_size: Observed TCP window size

        Returns:
            Tuple of (OSFamily, confidence, details)
        """
        os_guesses = []
        details_parts = []

        # Analyze TTL
        if ttl:
            if ttl in self.TTL_SIGNATURES:
                os_family = self.TTL_SIGNATURES[ttl]
                os_guesses.append((os_family, 0.6))
                details_parts.append(f"TTL={ttl}")

        # Analyze window size
        if window_size:
            if window_size in self.WINDOW_SIGNATURES:
                os_family = self.WINDOW_SIGNATURES[window_size]
                os_guesses.append((os_family, 0.5))
                details_parts.append(f"Window={window_size}")

        # Combine guesses
        if os_guesses:
            # Simple voting - take most common guess
            os_counts: Dict[OSFamily, float] = {}
            for os_family, conf in os_guesses:
                os_counts[os_family] = os_counts.get(os_family, 0.0) + conf

            # Get best guess
            best_os = max(os_counts.items(), key=lambda x: x[1])
            os_family = best_os[0]
            confidence = min(best_os[1], 0.7)  # Cap confidence at 0.7

            details = f"Best effort guess based on: {', '.join(details_parts)}"

            return os_family, confidence, details

        else:
            # No data collected
            return (
                OSFamily.UNKNOWN,
                0.0,
                "Insufficient data for OS fingerprinting"
            )
