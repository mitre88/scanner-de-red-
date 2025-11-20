"""
Reporting and output formatting module.

Handles formatting scan results for different output formats
including human-readable console output and JSON.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import asdict

from .discovery import HostStatus
from .scanner import ScanResult, PortState
from .services import ServiceInfo
from .fingerprint import OSFingerprint, OSFamily


class Reporter:
    """
    Formats and outputs scan results in various formats.

    Supports:
    - Human-readable console output
    - JSON format for machine parsing
    """

    @staticmethod
    def format_text(
        scan_data: Dict[str, Any],
        verbose: bool = False
    ) -> str:
        """
        Format scan results as human-readable text.

        Args:
            scan_data: Dictionary containing scan results
            verbose: Include verbose information

        Returns:
            Formatted text string
        """
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append("Network Scanner Report")
        lines.append("=" * 70)
        lines.append("")

        # Scan metadata
        metadata = scan_data.get('metadata', {})
        lines.append(f"Scan Date: {metadata.get('scan_date', 'N/A')}")
        lines.append(f"Scan Duration: {metadata.get('total_duration', 'N/A')}")
        lines.append(f"Targets Scanned: {metadata.get('total_targets', 0)}")
        lines.append(f"Hosts Up: {metadata.get('hosts_up', 0)}")
        lines.append("")

        # Scan parameters
        params = scan_data.get('scan_parameters', {})
        if params:
            lines.append("Scan Parameters:")
            if 'ports' in params:
                lines.append(f"  TCP Ports: {params['ports']}")
            if 'udp_ports' in params and params['udp_ports']:
                lines.append(f"  UDP Ports: {params['udp_ports']}")
            lines.append(f"  Timeout: {params.get('timeout', 'N/A')}s")
            lines.append(f"  Workers: {params.get('workers', 'N/A')}")
            lines.append("")

        # Host results
        hosts = scan_data.get('hosts', [])

        if not hosts:
            lines.append("No hosts discovered.")
        else:
            for host_data in hosts:
                lines.extend(Reporter._format_host_text(host_data, verbose))
                lines.append("")

        # Footer
        lines.append("=" * 70)
        lines.append("Scan Complete")
        lines.append("=" * 70)

        return "\n".join(lines)

    @staticmethod
    def _format_host_text(host_data: Dict[str, Any], verbose: bool) -> List[str]:
        """Format a single host's results as text."""
        lines = []

        ip = host_data.get('ip', 'Unknown')
        status = host_data.get('status', {})

        # Host header
        lines.append("-" * 70)
        lines.append(f"Host: {ip}")
        lines.append("-" * 70)

        # Host status
        if status:
            is_alive = status.get('is_alive', False)
            status_str = "UP" if is_alive else "DOWN"
            lines.append(f"Status: {status_str}")

            if status.get('rtt'):
                lines.append(f"RTT: {status['rtt']:.2f}ms")

            if status.get('method'):
                lines.append(f"Discovery Method: {status['method']}")

        # OS fingerprint
        os_info = host_data.get('os_fingerprint')
        if os_info and os_info.get('os_family') != 'Unknown':
            os_family = os_info.get('os_family', 'Unknown')
            confidence = os_info.get('confidence', 0)
            lines.append(f"OS Guess: {os_family} (confidence: {confidence:.1%})")

            if verbose and os_info.get('details'):
                lines.append(f"  Details: {os_info['details']}")

        # Open ports
        scan_results = host_data.get('scan_results', {})

        tcp_results = scan_results.get('tcp', {})
        tcp_ports = tcp_results.get('ports', [])
        open_tcp = [p for p in tcp_ports if p.get('state') == 'open']

        if open_tcp:
            lines.append(f"\nOpen TCP Ports ({len(open_tcp)}):")
            lines.append(f"{'PORT':<8} {'STATE':<12} {'SERVICE':<15} {'VERSION':<30}")
            lines.append("-" * 70)

            for port in open_tcp:
                port_num = port.get('port', 0)
                state = port.get('state', 'unknown')
                service = port.get('service', 'unknown')

                # Get service details if available
                version = ""
                services = host_data.get('services', {})
                if str(port_num) in services:
                    svc = services[str(port_num)]
                    if svc.get('product'):
                        version = svc['product']
                    elif svc.get('version'):
                        version = svc['version']

                lines.append(
                    f"{port_num:<8} {state:<12} {service:<15} {version:<30}"
                )

                # Verbose: show banner
                if verbose and str(port_num) in services:
                    svc = services[str(port_num)]
                    if svc.get('banner'):
                        banner = svc['banner'][:60]
                        lines.append(f"  Banner: {banner}")

        # UDP ports
        udp_results = scan_results.get('udp', {})
        udp_ports = udp_results.get('ports', [])
        open_udp = [p for p in udp_ports if 'open' in p.get('state', '').lower()]

        if open_udp:
            lines.append(f"\nOpen/Filtered UDP Ports ({len(open_udp)}):")
            lines.append(f"{'PORT':<8} {'STATE':<15} {'SERVICE':<15}")
            lines.append("-" * 40)

            for port in open_udp:
                port_num = port.get('port', 0)
                state = port.get('state', 'unknown')
                service = port.get('service', 'unknown')

                lines.append(f"{port_num:<8} {state:<15} {service:<15}")

        # Show message if no open ports
        if not open_tcp and not open_udp:
            lines.append("\nNo open ports detected.")

        return lines

    @staticmethod
    def format_json(
        scan_data: Dict[str, Any],
        pretty: bool = True
    ) -> str:
        """
        Format scan results as JSON.

        Args:
            scan_data: Dictionary containing scan results
            pretty: Whether to pretty-print the JSON

        Returns:
            JSON string
        """
        if pretty:
            return json.dumps(scan_data, indent=2, default=str)
        else:
            return json.dumps(scan_data, default=str)

    @staticmethod
    def save_to_file(content: str, filepath: str) -> None:
        """
        Save report content to a file.

        Args:
            content: Report content to save
            filepath: Path to output file
        """
        try:
            with open(filepath, 'w') as f:
                f.write(content)
        except Exception as e:
            raise IOError(f"Failed to write report to {filepath}: {e}")

    @staticmethod
    def build_scan_data(
        hosts_status: Dict[str, HostStatus],
        scan_results: Dict[str, Dict[str, ScanResult]],
        services: Dict[str, Dict[int, ServiceInfo]],
        os_fingerprints: Dict[str, OSFingerprint],
        metadata: Dict[str, Any],
        scan_parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build complete scan data structure from individual results.

        Args:
            hosts_status: Host discovery results
            scan_results: Port scan results
            services: Service detection results
            os_fingerprints: OS fingerprinting results
            metadata: Scan metadata
            scan_parameters: Scan parameters

        Returns:
            Complete scan data dictionary
        """
        hosts = []

        for ip in hosts_status:
            host_data = {
                'ip': ip,
                'status': {
                    'is_alive': hosts_status[ip].is_alive,
                    'rtt': hosts_status[ip].rtt,
                    'method': hosts_status[ip].method,
                    'timestamp': hosts_status[ip].timestamp.isoformat()
                }
            }

            # Add scan results
            if ip in scan_results:
                host_scan_results = {}

                if 'tcp' in scan_results[ip]:
                    tcp_result = scan_results[ip]['tcp']
                    host_scan_results['tcp'] = {
                        'ports': [
                            {
                                'port': p.port,
                                'state': p.state.value,
                                'service': p.service,
                                'timestamp': p.timestamp.isoformat()
                            }
                            for p in tcp_result.ports
                        ],
                        'scan_duration': tcp_result.scan_duration
                    }

                if 'udp' in scan_results[ip]:
                    udp_result = scan_results[ip]['udp']
                    host_scan_results['udp'] = {
                        'ports': [
                            {
                                'port': p.port,
                                'state': p.state.value,
                                'service': p.service,
                                'timestamp': p.timestamp.isoformat()
                            }
                            for p in udp_result.ports
                        ],
                        'scan_duration': udp_result.scan_duration
                    }

                host_data['scan_results'] = host_scan_results

            # Add services
            if ip in services:
                host_services = {}
                for port, service_info in services[ip].items():
                    host_services[str(port)] = {
                        'service': service_info.service,
                        'version': service_info.version,
                        'banner': service_info.banner,
                        'product': service_info.product,
                        'extra_info': service_info.extra_info
                    }
                host_data['services'] = host_services

            # Add OS fingerprint
            if ip in os_fingerprints:
                fp = os_fingerprints[ip]
                host_data['os_fingerprint'] = {
                    'os_family': fp.os_family.value,
                    'confidence': fp.confidence,
                    'details': fp.details,
                    'ttl': fp.ttl,
                    'window_size': fp.window_size,
                    'characteristics': fp.characteristics
                }

            hosts.append(host_data)

        return {
            'metadata': metadata,
            'scan_parameters': scan_parameters,
            'hosts': hosts
        }
