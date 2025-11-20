"""
Command-line interface for the network scanner.

Provides argument parsing and orchestrates the scanning process.
"""

import argparse
import sys
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

from .utils import (
    parse_targets,
    parse_port_range,
    get_common_ports,
    get_common_udp_ports,
    validate_timeout,
    validate_workers,
    format_duration
)
from .discovery import HostDiscovery, HostStatus
from .scanner import PortScanner, ScanResult
from .services import ServiceDetector, ServiceInfo
from .fingerprint import OSFingerprinter, OSFingerprint
from .reporter import Reporter


# Legal/Ethical warning banner
BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║                     NETWORK SCANNER v1.0                           ║
║                  AUTHORIZED USE ONLY WARNING                       ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  This tool is intended ONLY for authorized security testing,      ║
║  internal network audits, and legitimate blue-team operations.    ║
║                                                                    ║
║  You are responsible for:                                         ║
║  • Ensuring you have explicit permission to scan target systems   ║
║  • Complying with all applicable laws and regulations             ║
║  • Following your organization's security policies                ║
║                                                                    ║
║  Unauthorized network scanning may be illegal and could result    ║
║  in criminal prosecution and/or civil liability.                  ║
║                                                                    ║
║  By using this tool, you acknowledge that you have proper         ║
║  authorization and accept full responsibility for your actions.   ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
"""


class NetworkScannerCLI:
    """
    Command-line interface for network scanning operations.

    Orchestrates the entire scanning workflow including:
    - Host discovery
    - Port scanning
    - Service detection
    - OS fingerprinting
    - Report generation
    """

    def __init__(self):
        """Initialize the CLI."""
        self.logger = logging.getLogger(__name__)

    def create_parser(self) -> argparse.ArgumentParser:
        """
        Create and configure argument parser.

        Returns:
            Configured ArgumentParser
        """
        parser = argparse.ArgumentParser(
            description="Professional network scanner for authorized security assessments",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Scan single host on common ports
  %(prog)s --targets 192.168.1.1

  # Scan network range with specific ports
  %(prog)s --targets 192.168.1.0/24 --ports 22,80,443

  # Scan with UDP and save JSON output
  %(prog)s --targets 10.0.0.0/28 --ports 1-1024 --udp --output-format json --output-file results.json

  # Verbose scan with service detection
  %(prog)s --targets 192.168.1.10 --ports 1-65535 --verbose --detect-services

For detailed documentation, see README.md
            """
        )

        # Target specification
        parser.add_argument(
            '--targets',
            type=str,
            required=True,
            help='Target specification: IP, comma-separated IPs, or CIDR (e.g., "192.168.1.0/24")'
        )

        # Port specification
        parser.add_argument(
            '--ports',
            type=str,
            default='common',
            help='Ports to scan: "common", "1-1024", "80,443", etc. (default: common)'
        )

        parser.add_argument(
            '--udp',
            action='store_true',
            help='Enable UDP port scanning (limited reliability)'
        )

        parser.add_argument(
            '--udp-ports',
            type=str,
            help='UDP ports to scan (default: common UDP ports)'
        )

        # Timing and performance
        parser.add_argument(
            '--timeout',
            type=float,
            default=2.0,
            help='Timeout per connection in seconds (default: 2.0)'
        )

        parser.add_argument(
            '--workers',
            type=int,
            default=100,
            help='Number of concurrent workers (default: 100)'
        )

        # Feature flags
        parser.add_argument(
            '--no-discovery',
            action='store_true',
            help='Skip host discovery, assume all targets are up'
        )

        parser.add_argument(
            '--detect-services',
            action='store_true',
            help='Enable service detection and banner grabbing'
        )

        parser.add_argument(
            '--os-fingerprint',
            action='store_true',
            help='Enable OS fingerprinting (best effort)'
        )

        # Output options
        parser.add_argument(
            '--output-format',
            choices=['text', 'json'],
            default='text',
            help='Output format (default: text)'
        )

        parser.add_argument(
            '--output-file',
            type=str,
            help='Save output to file instead of stdout'
        )

        parser.add_argument(
            '--verbose',
            '-v',
            action='store_true',
            help='Enable verbose output'
        )

        parser.add_argument(
            '--quiet',
            '-q',
            action='store_true',
            help='Suppress banner and progress messages'
        )

        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            default='INFO',
            help='Set logging level (default: INFO)'
        )

        return parser

    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the scanner with provided arguments.

        Args:
            args: Command-line arguments (None = use sys.argv)

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)

        # Setup logging
        log_level = getattr(logging, parsed_args.log_level)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Show banner unless quiet
        if not parsed_args.quiet:
            print(BANNER)
            print()

        try:
            # Validate and parse inputs
            targets = parse_targets(parsed_args.targets)
            timeout = validate_timeout(parsed_args.timeout)
            workers = validate_workers(parsed_args.workers)

            # Parse ports
            if parsed_args.ports.lower() == 'common':
                tcp_ports = get_common_ports()
            else:
                tcp_ports = parse_port_range(parsed_args.ports)

            # Parse UDP ports if enabled
            udp_ports = None
            if parsed_args.udp:
                if parsed_args.udp_ports:
                    udp_ports = parse_port_range(parsed_args.udp_ports)
                else:
                    udp_ports = get_common_udp_ports()

            # Show scan summary
            if not parsed_args.quiet:
                print(f"[*] Starting scan at {datetime.now()}")
                print(f"[*] Targets: {len(targets)} host(s)")
                print(f"[*] TCP Ports: {len(tcp_ports)} port(s)")
                if udp_ports:
                    print(f"[*] UDP Ports: {len(udp_ports)} port(s)")
                print(f"[*] Timeout: {timeout}s")
                print(f"[*] Workers: {workers}")
                print()

            # Run the scan
            scan_start = time.time()
            results = self._execute_scan(
                targets=targets,
                tcp_ports=tcp_ports,
                udp_ports=udp_ports,
                timeout=timeout,
                workers=workers,
                skip_discovery=parsed_args.no_discovery,
                detect_services=parsed_args.detect_services,
                os_fingerprint=parsed_args.os_fingerprint,
                quiet=parsed_args.quiet
            )
            scan_duration = time.time() - scan_start

            # Build scan data
            metadata = {
                'scan_date': datetime.now().isoformat(),
                'total_duration': format_duration(scan_duration),
                'total_targets': len(targets),
                'hosts_up': sum(1 for h in results['hosts_status'].values() if h.is_alive)
            }

            scan_parameters = {
                'targets': parsed_args.targets,
                'ports': parsed_args.ports,
                'udp_enabled': parsed_args.udp,
                'timeout': timeout,
                'workers': workers,
                'detect_services': parsed_args.detect_services,
                'os_fingerprint': parsed_args.os_fingerprint
            }

            scan_data = Reporter.build_scan_data(
                hosts_status=results['hosts_status'],
                scan_results=results['scan_results'],
                services=results['services'],
                os_fingerprints=results['os_fingerprints'],
                metadata=metadata,
                scan_parameters=scan_parameters
            )

            # Generate report
            if parsed_args.output_format == 'json':
                output = Reporter.format_json(scan_data)
            else:
                output = Reporter.format_text(scan_data, verbose=parsed_args.verbose)

            # Output results
            if parsed_args.output_file:
                Reporter.save_to_file(output, parsed_args.output_file)
                if not parsed_args.quiet:
                    print(f"\n[+] Report saved to: {parsed_args.output_file}")
            else:
                print(output)

            if not parsed_args.quiet:
                print(f"\n[+] Scan completed in {format_duration(scan_duration)}")

            return 0

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user", file=sys.stderr)
            return 130
        except Exception as e:
            print(f"\n[!] Error: {e}", file=sys.stderr)
            self.logger.exception("Scan failed")
            return 1

    def _execute_scan(
        self,
        targets: List[str],
        tcp_ports: List[int],
        udp_ports: Optional[List[int]],
        timeout: float,
        workers: int,
        skip_discovery: bool,
        detect_services: bool,
        os_fingerprint: bool,
        quiet: bool
    ) -> Dict:
        """
        Execute the scanning workflow.

        Args:
            targets: List of target IPs
            tcp_ports: TCP ports to scan
            udp_ports: UDP ports to scan (optional)
            timeout: Connection timeout
            workers: Number of workers
            skip_discovery: Skip host discovery phase
            detect_services: Enable service detection
            os_fingerprint: Enable OS fingerprinting
            quiet: Suppress progress messages

        Returns:
            Dictionary containing all scan results
        """
        results = {
            'hosts_status': {},
            'scan_results': {},
            'services': {},
            'os_fingerprints': {}
        }

        # Phase 1: Host Discovery
        if not quiet:
            print("[*] Phase 1: Host Discovery")

        if skip_discovery:
            # Assume all targets are up
            for ip in targets:
                results['hosts_status'][ip] = HostStatus(
                    ip=ip,
                    is_alive=True,
                    method='assumed'
                )
            alive_hosts = targets
        else:
            discovery = HostDiscovery(timeout=timeout, workers=workers)
            host_statuses = discovery.discover_hosts(targets)

            for host_status in host_statuses:
                results['hosts_status'][host_status.ip] = host_status

            alive_hosts = [
                h.ip for h in host_statuses if h.is_alive
            ]

            if not quiet:
                print(f"[+] Found {len(alive_hosts)} alive host(s)")

        if not alive_hosts:
            if not quiet:
                print("[!] No alive hosts found. Exiting.")
            return results

        # Phase 2: Port Scanning
        if not quiet:
            print(f"\n[*] Phase 2: Port Scanning ({len(alive_hosts)} host(s))")

        scanner = PortScanner(timeout=timeout, workers=workers)

        for i, ip in enumerate(alive_hosts, 1):
            if not quiet:
                print(f"[*] Scanning {ip} ({i}/{len(alive_hosts)})")

            scan_result = scanner.scan_host(
                ip=ip,
                tcp_ports=tcp_ports,
                udp_ports=udp_ports
            )

            results['scan_results'][ip] = scan_result

            if not quiet:
                tcp_open = len(scan_result.get('tcp', ScanResult(ip, [], 0)).get_open_ports())
                if tcp_open > 0:
                    print(f"  [+] Found {tcp_open} open TCP port(s)")

        # Phase 3: Service Detection
        if detect_services:
            if not quiet:
                print(f"\n[*] Phase 3: Service Detection")

            detector = ServiceDetector(timeout=timeout)

            for ip in alive_hosts:
                if ip in results['scan_results']:
                    # Get open TCP ports
                    tcp_result = results['scan_results'][ip].get('tcp')
                    if tcp_result:
                        open_ports = [p.port for p in tcp_result.get_open_ports()]

                        if open_ports:
                            if not quiet:
                                print(f"[*] Detecting services on {ip}")

                            services = detector.detect_services(ip, open_ports)
                            results['services'][ip] = services

        # Phase 4: OS Fingerprinting
        if os_fingerprint:
            if not quiet:
                print(f"\n[*] Phase 4: OS Fingerprinting")

            fingerprinter = OSFingerprinter(timeout=timeout)

            for ip in alive_hosts:
                if not quiet:
                    print(f"[*] Fingerprinting {ip}")

                # Get open ports to help with probing
                open_ports = None
                if ip in results['scan_results']:
                    tcp_result = results['scan_results'][ip].get('tcp')
                    if tcp_result:
                        open_ports = [p.port for p in tcp_result.get_open_ports()]

                fp = fingerprinter.fingerprint(ip, open_ports)
                results['os_fingerprints'][ip] = fp

        return results


def main():
    """Main entry point for CLI."""
    cli = NetworkScannerCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
