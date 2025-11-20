"""
Service detection and banner grabbing module.

Performs protocol-specific probes and banner grabbing
to identify services and their versions.
"""

import socket
import ssl
import re
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """
    Information about a detected service.

    Attributes:
        port: Port number
        service: Service name (e.g., "http", "ssh")
        version: Version string if detected
        banner: Raw banner text
        product: Product name if identified
        extra_info: Additional information
    """
    port: int
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None


class ServiceDetector:
    """
    Detects services and grabs banners from open ports.

    Uses protocol-specific probes and pattern matching
    to identify running services.
    """

    def __init__(self, timeout: float = 3.0):
        """
        Initialize service detector.

        Args:
            timeout: Timeout for service probes in seconds
        """
        self.timeout = timeout

    def detect_services(
        self,
        ip: str,
        ports: list[int],
        workers: int = 20
    ) -> Dict[int, ServiceInfo]:
        """
        Detect services on multiple ports.

        Args:
            ip: Target IP address
            ports: List of open port numbers
            workers: Number of concurrent workers

        Returns:
            Dictionary mapping port numbers to ServiceInfo objects
        """
        results = {}

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {
                executor.submit(self.detect_service, ip, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_info = future.result()
                    if service_info:
                        results[port] = service_info
                except Exception as e:
                    logger.debug(f"Error detecting service on {ip}:{port}: {e}")

        return results

    def detect_service(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """
        Detect service on a single port.

        Args:
            ip: Target IP address
            port: Port number

        Returns:
            ServiceInfo object or None
        """
        # Try different detection methods based on port
        if port == 80 or port == 8080:
            return self._detect_http(ip, port)
        elif port == 443 or port == 8443:
            return self._detect_https(ip, port)
        elif port == 22:
            return self._detect_ssh(ip, port)
        elif port == 21:
            return self._detect_ftp(ip, port)
        elif port == 25:
            return self._detect_smtp(ip, port)
        elif port == 3306:
            return self._detect_mysql(ip, port)
        elif port == 5432:
            return self._detect_postgresql(ip, port)
        elif port == 6379:
            return self._detect_redis(ip, port)
        else:
            # Generic banner grab
            return self._generic_banner_grab(ip, port)

    def _detect_http(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect HTTP service and grab server information."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send HTTP HEAD request
            request = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: NetworkScanner/1.0\r\n"
                f"\r\n"
            )
            sock.send(request.encode())

            # Receive response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            # Parse response
            version = None
            product = None
            extra = None

            # Extract Server header
            server_match = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
            if server_match:
                server = server_match.group(1).strip()
                product = server
                # Try to extract version
                version_match = re.search(r'/([\d.]+)', server)
                if version_match:
                    version = version_match.group(1)

            # Extract HTTP version
            http_version_match = re.search(r'HTTP/([\d.]+)', response)
            if http_version_match:
                extra = f"HTTP/{http_version_match.group(1)}"

            return ServiceInfo(
                port=port,
                service="http",
                version=version,
                banner=response[:200],  # Truncate
                product=product,
                extra_info=extra
            )

        except Exception as e:
            logger.debug(f"HTTP detection failed on {ip}:{port}: {e}")
            return None

    def _detect_https(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect HTTPS service and grab SSL/TLS information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Wrap with SSL
            ssl_sock = context.wrap_socket(sock, server_hostname=ip)

            # Get certificate info
            cert = ssl_sock.getpeercert()
            ssl_version = ssl_sock.version()

            # Send HTTP request
            request = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: NetworkScanner/1.0\r\n"
                f"\r\n"
            )
            ssl_sock.send(request.encode())

            response = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
            ssl_sock.close()

            # Extract server info
            product = None
            server_match = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
            if server_match:
                product = server_match.group(1).strip()

            extra = f"SSL/TLS: {ssl_version}" if ssl_version else None

            return ServiceInfo(
                port=port,
                service="https",
                version=ssl_version,
                banner=response[:200],
                product=product,
                extra_info=extra
            )

        except Exception as e:
            logger.debug(f"HTTPS detection failed on {ip}:{port}: {e}")
            return None

    def _detect_ssh(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect SSH service and version."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # SSH server sends banner first
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            # Parse SSH banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            product = None
            version = None

            if banner.startswith('SSH-'):
                parts = banner.split('-', 2)
                if len(parts) >= 3:
                    product = parts[2]
                    # Extract version number
                    version_match = re.search(r'[\d.]+', product)
                    if version_match:
                        version = version_match.group(0)

            return ServiceInfo(
                port=port,
                service="ssh",
                version=version,
                banner=banner,
                product=product
            )

        except Exception as e:
            logger.debug(f"SSH detection failed on {ip}:{port}: {e}")
            return None

    def _detect_ftp(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect FTP service and version."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # FTP sends banner on connect
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            # Parse FTP banner
            product = None
            version = None

            # Example: 220 ProFTPD 1.3.5 Server
            match = re.search(r'220\s+(.+)', banner)
            if match:
                product = match.group(1)
                version_match = re.search(r'([\d.]+)', product)
                if version_match:
                    version = version_match.group(1)

            return ServiceInfo(
                port=port,
                service="ftp",
                version=version,
                banner=banner,
                product=product
            )

        except Exception as e:
            logger.debug(f"FTP detection failed on {ip}:{port}: {e}")
            return None

    def _detect_smtp(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect SMTP service and version."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # SMTP sends banner on connect
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            # Parse SMTP banner
            product = None
            version = None

            # Example: 220 mail.example.com ESMTP Postfix
            match = re.search(r'220\s+(.+)', banner)
            if match:
                product = match.group(1)

            return ServiceInfo(
                port=port,
                service="smtp",
                version=version,
                banner=banner,
                product=product
            )

        except Exception as e:
            logger.debug(f"SMTP detection failed on {ip}:{port}: {e}")
            return None

    def _detect_mysql(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect MySQL service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # MySQL sends handshake packet
            data = sock.recv(1024)
            sock.close()

            if len(data) > 5:
                # Try to extract version from handshake
                # MySQL protocol: packet starts with protocol version
                # Followed by null-terminated version string
                try:
                    # Skip packet header (4 bytes)
                    protocol_version = data[4]
                    # Version string follows
                    version_end = data.find(b'\x00', 5)
                    if version_end > 5:
                        version = data[5:version_end].decode('utf-8', errors='ignore')
                        return ServiceInfo(
                            port=port,
                            service="mysql",
                            version=version,
                            product=f"MySQL {version}"
                        )
                except:
                    pass

            return ServiceInfo(
                port=port,
                service="mysql",
                product="MySQL"
            )

        except Exception as e:
            logger.debug(f"MySQL detection failed on {ip}:{port}: {e}")
            return None

    def _detect_postgresql(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect PostgreSQL service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send PostgreSQL startup packet
            # This is a simplified version
            startup = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
            sock.send(startup)

            response = sock.recv(1024)
            sock.close()

            # If we get a response, it's likely PostgreSQL
            if response:
                return ServiceInfo(
                    port=port,
                    service="postgresql",
                    product="PostgreSQL"
                )

        except Exception as e:
            logger.debug(f"PostgreSQL detection failed on {ip}:{port}: {e}")

        return None

    def _detect_redis(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Detect Redis service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send INFO command
            sock.send(b'*1\r\n$4\r\nINFO\r\n')
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            # Parse version from INFO response
            version = None
            version_match = re.search(r'redis_version:(\S+)', response)
            if version_match:
                version = version_match.group(1)

            return ServiceInfo(
                port=port,
                service="redis",
                version=version,
                product=f"Redis {version}" if version else "Redis"
            )

        except Exception as e:
            logger.debug(f"Redis detection failed on {ip}:{port}: {e}")
            return None

    def _generic_banner_grab(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Perform generic banner grabbing."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Try to receive banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                banner = None

            sock.close()

            if banner:
                return ServiceInfo(
                    port=port,
                    service="unknown",
                    banner=banner[:200]
                )

        except Exception as e:
            logger.debug(f"Generic banner grab failed on {ip}:{port}: {e}")

        return None
