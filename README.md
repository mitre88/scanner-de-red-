# Network Scanner

A professional-grade network scanner for authorized security assessments, internal audits, and blue-team operations.

## ⚠️ LEGAL WARNING

**This tool is intended ONLY for authorized security testing.**

- ✅ **Authorized use cases:** Internal network audits, penetration testing with permission, security assessments, blue-team operations
- ❌ **Prohibited use:** Unauthorized scanning, malicious activities, IDS/IPS evasion, exploitation

**By using this tool, you acknowledge:**
- You have explicit permission to scan target systems
- You comply with all applicable laws and regulations
- You follow your organization's security policies
- Unauthorized network scanning may be illegal and result in criminal prosecution

## Features

### Core Capabilities
- **Host Discovery**
  - ICMP ping sweep (when privileges allow)
  - TCP-based discovery (fallback method)
  - Support for single IPs, lists, and CIDR ranges

- **Port Scanning**
  - TCP connect scanning (no root required)
  - UDP scanning with protocol-specific probes
  - Concurrent scanning for performance
  - Configurable timeouts and worker threads

- **Service Detection**
  - Protocol-specific banner grabbing
  - Version detection for common services
  - Support for HTTP/HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, and more

- **OS Fingerprinting**
  - Best-effort OS detection
  - Based on TTL values and TCP characteristics
  - Confidence scoring

- **Reporting**
  - Human-readable console output
  - JSON format for automation
  - File output support
  - Detailed verbose mode

## Requirements

- Python 3.11 or higher
- No external dependencies required (uses standard library)

## Installation

### Clone the Repository
```bash
git clone <repository-url>
cd scanner-de-red-
```

### Verify Python Version
```bash
python --version  # Should be 3.11+
```

### Optional: Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Make Main Script Executable (Optional)
```bash
chmod +x main.py
```

## Usage

### Basic Syntax
```bash
python main.py --targets <TARGET> [OPTIONS]
```

### Example Commands

#### 1. Scan a Single Host (Common Ports)
```bash
python main.py --targets 192.168.1.1
```

#### 2. Scan a Network Range (/24)
```bash
python main.py --targets 192.168.1.0/24
```

#### 3. Scan Specific Ports
```bash
python main.py --targets 192.168.1.10 --ports 22,80,443,3306,5432
```

#### 4. Scan Port Range
```bash
python main.py --targets 192.168.1.10 --ports 1-1024
```

#### 5. Enable UDP Scanning
```bash
python main.py --targets 192.168.1.1 --udp
```

#### 6. Full Scan with All Features
```bash
python main.py --targets 192.168.1.0/24 \
  --ports 1-1024 \
  --udp \
  --detect-services \
  --os-fingerprint \
  --verbose
```

#### 7. Save Results to JSON File
```bash
python main.py --targets 192.168.1.0/24 \
  --ports common \
  --output-format json \
  --output-file scan_results.json
```

#### 8. Fast Scan (More Workers, Lower Timeout)
```bash
python main.py --targets 192.168.1.0/24 \
  --ports common \
  --timeout 0.5 \
  --workers 200
```

#### 9. Scan Multiple Targets
```bash
python main.py --targets 192.168.1.1,192.168.1.10,10.0.0.1
```

#### 10. Quiet Mode (No Banner)
```bash
python main.py --targets 192.168.1.1 --quiet
```

### Command-Line Options

```
Required Arguments:
  --targets TARGET      Target specification: IP, comma-separated IPs, or CIDR
                        Examples: "192.168.1.1", "192.168.1.0/24", "10.0.0.1,10.0.0.2"

Port Options:
  --ports PORTS         Ports to scan (default: common)
                        Examples: "common", "1-1024", "80,443,8080", "1-65535"
  --udp                 Enable UDP port scanning
  --udp-ports PORTS     UDP ports to scan (default: common UDP ports)

Performance Options:
  --timeout SECONDS     Timeout per connection in seconds (default: 2.0)
  --workers COUNT       Number of concurrent workers (default: 100)

Feature Options:
  --no-discovery        Skip host discovery, assume all targets are up
  --detect-services     Enable service detection and banner grabbing
  --os-fingerprint      Enable OS fingerprinting (best effort)

Output Options:
  --output-format FMT   Output format: text or json (default: text)
  --output-file FILE    Save output to file instead of stdout
  --verbose, -v         Enable verbose output
  --quiet, -q           Suppress banner and progress messages
  --log-level LEVEL     Set logging level: DEBUG, INFO, WARNING, ERROR

Help:
  --help, -h            Show help message and exit
```

## Architecture

### Project Structure
```
scanner-de-red-/
├── scanner/
│   ├── __init__.py         # Package initialization
│   ├── cli.py              # Command-line interface
│   ├── discovery.py        # Host discovery (ICMP, TCP)
│   ├── scanner.py          # Port scanning (TCP, UDP)
│   ├── services.py         # Service detection & banner grabbing
│   ├── fingerprint.py      # OS fingerprinting
│   ├── reporter.py         # Output formatting (text, JSON)
│   └── utils.py            # Utilities (IP/port parsing, validation)
├── tests/
│   ├── __init__.py
│   ├── test_utils.py       # Utility function tests
│   ├── test_discovery.py   # Host discovery tests
│   └── test_scanner.py     # Port scanner tests
├── main.py                 # Main entry point
├── README.md               # This file
└── requirements.txt        # Dependencies (minimal)
```

### Module Descriptions

#### `utils.py`
- IP address and CIDR range parsing
- Port range parsing and validation
- Input validation and sanitization
- Helper functions

#### `discovery.py`
- ICMP ping sweep (requires raw socket privileges)
- TCP-based host discovery (fallback)
- Concurrent host probing
- RTT measurement

#### `scanner.py`
- TCP connect scanning
- UDP port probing
- Service name mapping
- Concurrent port scanning

#### `services.py`
- Protocol-specific banner grabbing
- Service version detection
- Support for: HTTP, HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis
- Generic banner grabbing for unknown services

#### `fingerprint.py`
- Best-effort OS detection
- TTL-based fingerprinting
- TCP window size analysis (limited without raw sockets)
- Confidence scoring

#### `reporter.py`
- Human-readable text formatting
- JSON output for automation
- File export functionality
- Verbose and quiet modes

#### `cli.py`
- Argument parsing with argparse
- Workflow orchestration
- Progress reporting
- Error handling

## Running Tests

The project includes unit tests for core functionality.

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Run Specific Test File
```bash
python -m pytest tests/test_utils.py -v
```

### Run with Coverage (if pytest-cov installed)
```bash
pip install pytest pytest-cov
python -m pytest tests/ --cov=scanner --cov-report=html
```

## Design Decisions & Limitations

### TCP Connect Scanning
**Decision:** Use TCP connect() instead of SYN scanning.

**Rationale:**
- No root/admin privileges required
- More portable across systems
- Sufficient for authorized assessments

**Limitation:**
- Slower than SYN scanning
- Logged by target systems

### UDP Scanning
**Decision:** Basic UDP probing with protocol-specific packets.

**Rationale:**
- Provides coverage for common UDP services
- Works without raw sockets for basic cases

**Limitation:**
- UDP is inherently unreliable
- Can't distinguish between filtered and open ports reliably
- No response doesn't guarantee port is closed

### OS Fingerprinting
**Decision:** Simple TTL-based fingerprinting.

**Rationale:**
- Works without external databases
- Provides basic OS family detection

**Limitation:**
- Low confidence without extensive signatures
- Limited to TTL analysis (window size requires raw sockets)
- Should be considered "best effort" only

### Concurrency Model
**Decision:** ThreadPoolExecutor for concurrent operations.

**Rationale:**
- Simple and reliable
- Sufficient for I/O-bound network operations
- No external dependencies

**Alternative:** Could use asyncio for potentially better performance, but adds complexity.

### No External Dependencies
**Decision:** Use only Python standard library.

**Rationale:**
- Easy deployment
- Minimal attack surface
- No dependency conflicts

**Trade-off:** Some features (like advanced packet crafting) would be easier with libraries like Scapy, but requiring minimal dependencies was prioritized.

## Performance Tips

### Optimize for Large Networks
```bash
# Increase workers and decrease timeout for faster scans
python main.py --targets 192.168.0.0/16 \
  --ports common \
  --timeout 0.5 \
  --workers 500 \
  --no-discovery  # Skip discovery if you know hosts are up
```

### Detailed Analysis of Few Hosts
```bash
# Lower workers, higher timeout, enable all features
python main.py --targets 192.168.1.10,192.168.1.20 \
  --ports 1-65535 \
  --timeout 3.0 \
  --workers 50 \
  --detect-services \
  --os-fingerprint \
  --verbose
```

## Troubleshooting

### ICMP Not Working
**Error:** "ICMP not available, using TCP-based discovery"

**Cause:** Insufficient privileges for raw sockets.

**Solution:**
```bash
# Linux: Run with sudo (use cautiously)
sudo python main.py --targets 192.168.1.0/24

# Or: Set capabilities (Linux only)
sudo setcap cap_net_raw+ep $(which python3)
```

### Permission Denied Errors
**Cause:** Trying to scan privileged ports or use ICMP without permissions.

**Solution:** Use TCP-based discovery, or run with appropriate privileges in authorized environments.

### Timeout Errors
**Cause:** Network latency or firewall filtering.

**Solution:** Increase timeout value:
```bash
python main.py --targets <target> --timeout 5.0
```

### Slow Scans
**Cause:** Too few workers or too many ports.

**Solution:** Increase workers or scan fewer ports:
```bash
python main.py --targets <target> --workers 200 --timeout 0.5
```

## Security Best Practices

1. **Always get authorization** before scanning any network
2. **Document your activities** - keep logs of what you scan and when
3. **Use least privilege** - don't run as root unless necessary
4. **Respect rate limits** - don't overwhelm target systems
5. **Follow responsible disclosure** - if you find vulnerabilities, report them properly
6. **Stay within scope** - only scan systems you're authorized to test

## Contributing

This is a reference implementation for educational and authorized security testing purposes.

### Code Quality Standards
- Type hints throughout
- Docstrings for all public functions
- Unit tests for core functionality
- Clean, modular architecture

## License

This tool is provided for educational and authorized security testing purposes only. Users are solely responsible for ensuring their use complies with applicable laws and regulations.

## Support

For issues, questions, or contributions:
1. Check the documentation above
2. Review existing issues
3. Create a detailed issue report if needed

## Changelog

### Version 1.0.0
- Initial release
- Host discovery (ICMP, TCP)
- TCP/UDP port scanning
- Service detection
- OS fingerprinting
- Text and JSON output
- Comprehensive CLI

## Acknowledgments

Built using Python standard library, following security best practices for authorized network assessment tools.

---

**Remember: With great power comes great responsibility. Always use this tool ethically and legally.**
