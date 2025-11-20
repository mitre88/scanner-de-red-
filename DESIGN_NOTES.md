# Network Scanner - Design Notes

## Architecture Overview

The network scanner is built with a modular architecture, separating concerns into distinct modules. This design promotes maintainability, testability, and extensibility.

### Core Principles

1. **Modularity**: Each module handles a specific responsibility
2. **Standard Library Only**: Minimize external dependencies
3. **Type Safety**: Use type hints throughout
4. **Error Handling**: Graceful degradation and clear error messages
5. **Security**: No exploitation features, designed for authorized testing only

## Module Design

### utils.py - Utility Functions

**Purpose**: Input parsing, validation, and helper functions

**Key Functions**:
- `parse_targets()`: Converts user input (IP, CIDR) into list of IPs
- `parse_port_range()`: Converts port specifications into port lists
- Input validation with clear error messages

**Design Decisions**:
- Limit network sizes (max /16) to prevent accidental massive scans
- Validate all inputs before processing
- Return sorted lists for predictable output

**Trade-offs**:
- Strict validation may reject some edge cases
- Could be more permissive, but safety prioritized

### discovery.py - Host Discovery

**Purpose**: Determine which hosts are alive on the network

**Techniques**:
1. **ICMP Ping** (preferred)
   - Fast and reliable
   - Requires raw socket privileges
   - Falls back if not available

2. **TCP-based Discovery** (fallback)
   - Works without special privileges
   - Tries common ports (80, 443, 22, etc.)
   - Slower but reliable

**Design Decisions**:
- Auto-detect available privileges
- Graceful fallback to TCP if ICMP unavailable
- Concurrent probing with ThreadPoolExecutor
- Measure RTT for diagnostics

**Limitations**:
- ICMP may be blocked by firewalls
- TCP discovery only tries limited ports
- No ARP-based discovery (would require raw sockets and same subnet)

**Performance**:
- Default 50 workers balances speed and resource usage
- Configurable for different scenarios

### scanner.py - Port Scanning

**Purpose**: Enumerate open ports on discovered hosts

**Scanning Methods**:

1. **TCP Connect Scanning**
   - Uses socket.connect_ex()
   - No root privileges required
   - Reliable and portable
   - Slower than SYN scanning
   - Fully completes TCP handshake

2. **UDP Scanning**
   - Sends UDP probes
   - Protocol-specific payloads for known services
   - Unreliable due to UDP nature
   - Can't distinguish filtered vs open reliably

**Design Decisions**:
- TCP connect instead of SYN scanning
  - Rationale: No root required, more portable
  - Trade-off: Slower, leaves logs on target

- Only report open ports by default
  - Reduces noise in output
  - Closed/filtered ports available in verbose mode

- Service name mapping
  - Built-in common service names
  - No need for external service files

**Concurrency Model**:
- ThreadPoolExecutor for I/O-bound operations
- Default 100 workers
- Each port scan is independent task

**Limitations**:
- TCP connect is slower than SYN scanning
- UDP scanning inherently unreliable
- No stealth scanning techniques
- All connections are logged by target systems

### services.py - Service Detection

**Purpose**: Identify services and versions on open ports

**Detection Methods**:

1. **Protocol-Specific Probes**
   - HTTP/HTTPS: Send HEAD request, parse Server header
   - SSH: Read banner
   - FTP: Read welcome banner
   - SMTP: Read greeting
   - MySQL: Parse handshake packet
   - PostgreSQL: Send startup packet
   - Redis: Send INFO command

2. **Generic Banner Grabbing**
   - Connect and wait for banner
   - Fallback for unknown services

**Design Decisions**:
- Implement common protocols manually
  - No dependency on external libraries
  - Protocol knowledge embedded in code

- Timeout handling
  - Services may not respond immediately
  - Balance between accuracy and speed

- SSL/TLS support
  - Use Python's ssl module
  - Extract certificate information
  - Handle SSL negotiation

**Limitations**:
- Limited to protocols we've implemented
- Some services require complex handshakes
- Banner grabbing may not work for all services
- No active fingerprinting (intentional, to avoid triggering IDS)

**Security Considerations**:
- No exploitation attempts
- Read-only operations
- Minimal interaction with services
- No authentication attempts

### fingerprint.py - OS Fingerprinting

**Purpose**: Best-effort OS detection using passive techniques

**Techniques**:

1. **TTL-based Detection**
   - Common initial TTL values:
     - 64: Linux, Unix
     - 128: Windows
     - 255: Network devices, some Unix
   - Estimate initial TTL from observed value

2. **TCP Window Size** (limited)
   - Would require raw socket access
   - Can't reliably capture SYN-ACK packets
   - Placeholder implementation

**Design Decisions**:
- Simple heuristics without external databases
  - No signature database to maintain
  - Fast and lightweight

- Low confidence scoring
  - Acknowledge limitations
  - Never claim high confidence

- Passive observation only
  - No active fingerprinting packets
  - Use data already collected

**Limitations**:
- **Major Limitation**: Without raw socket access, we can't capture detailed TCP characteristics
- TTL alone is unreliable (can be modified, affected by routing)
- Window size detection not implemented (needs packet capture)
- No TCP options analysis
- Should be considered "best guess" only

**Future Improvements**:
- Could integrate with Scapy for advanced fingerprinting
- Add more TCP stack characteristics
- Machine learning on collected features

**Why Not More Advanced?**:
- Keeping dependencies minimal
- Advanced fingerprinting requires root privileges
- Risk of false positives
- Not critical for authorized scanning

### reporter.py - Output Formatting

**Purpose**: Format scan results for human and machine consumption

**Output Formats**:

1. **Text Output**
   - Human-readable
   - Organized by host
   - Table formatting for ports
   - Summary statistics
   - Verbose mode for additional details

2. **JSON Output**
   - Machine-parsable
   - Structured data
   - Includes all metadata
   - Timestamps in ISO format
   - Can be processed by other tools

**Design Decisions**:
- Separate formatting from scanning logic
  - Clean separation of concerns
  - Easy to add new formats

- Include metadata
  - Scan parameters
  - Timestamps
  - Duration
  - Helps with reporting and auditing

- File output support
  - Save results for later analysis
  - Archive scan results

**Limitations**:
- Only two formats (text, JSON)
- Could add XML, CSV, HTML reports
- No real-time progress in output (by design)

### cli.py - Command-Line Interface

**Purpose**: Orchestrate the scanning workflow and handle user interaction

**Workflow**:
1. Parse and validate arguments
2. Show legal warning banner
3. Phase 1: Host Discovery
4. Phase 2: Port Scanning
5. Phase 3: Service Detection (if enabled)
6. Phase 4: OS Fingerprinting (if enabled)
7. Generate and output report

**Design Decisions**:
- Clear phase separation
  - User can see progress
  - Easy to debug

- Legal warning banner
  - Emphasizes authorized use
  - Can't be disabled (quiet mode still shows it)

- Sensible defaults
  - Common ports by default
  - Reasonable timeout and workers
  - Safe for small networks

- Progressive enhancement
  - Basic scan is fast
  - Optional features add depth
  - User controls trade-offs

**Error Handling**:
- Validate all inputs before scanning
- Clear error messages
- Graceful degradation (e.g., ICMP fallback)
- Catch KeyboardInterrupt for clean exit

## Performance Considerations

### Concurrency Model

**Choice**: ThreadPoolExecutor

**Rationale**:
- I/O-bound operations benefit from threading
- Simpler than asyncio
- No GIL issues for network I/O
- Standard library, no dependencies

**Alternative Considered**: asyncio
- Pros: Potentially better performance, modern Python
- Cons: More complex code, harder to debug, not significantly better for this use case

### Default Parameters

- **Timeout**: 2.0 seconds
  - Balance between accuracy and speed
  - Longer for high-latency networks
  - Shorter for LANs

- **Workers**: 100 (scanning), 50 (discovery)
  - Conservative to avoid overwhelming systems
  - Can be increased for faster scans
  - System resource consideration

### Optimization Opportunities

1. **Connection pooling**: Reuse sockets where possible
2. **Adaptive timeout**: Adjust based on RTT
3. **Smart port ordering**: Scan common ports first
4. **Result caching**: Avoid re-scanning recently scanned hosts

## Security and Ethics

### Prohibited Features

**Deliberately NOT Implemented**:
- Exploitation of vulnerabilities
- Brute force attacks
- Password guessing
- IDS/IPS evasion techniques
- Stealth scanning modes
- Packet fragmentation for evasion
- Timing attacks

**Rationale**: This tool is for authorized assessment only. Offensive capabilities would enable misuse.

### Safe Defaults

- Reasonable rate limits (worker count)
- No aggressive retries
- Clear logging of activities
- Obvious user-agent strings
- Full TCP handshake (not stealthy)

### Responsible Design

- Legal warning banner
- Documentation emphasizes authorization
- Code comments explain limitations
- No "hack mode" or similar features

## Limitations and Trade-offs

### By Design

1. **No Root Required** (mostly)
   - Trade-off: Can't do SYN scanning or advanced fingerprinting
   - Benefit: Easier to deploy, safer to run

2. **Standard Library Only**
   - Trade-off: Some features harder to implement
   - Benefit: No dependencies, easy installation

3. **No Exploitation**
   - Trade-off: Can't verify vulnerabilities
   - Benefit: Ethical, legal compliance

### Technical Limitations

1. **TCP Connect Scanning**
   - Slower than SYN scanning
   - Logged by target systems
   - Can't scan your own machine reliably (some ports)

2. **UDP Scanning**
   - Inherently unreliable
   - Can't distinguish filtered/open
   - Depends on ICMP unreachable messages

3. **OS Fingerprinting**
   - Low accuracy without raw sockets
   - Limited to basic heuristics
   - Should not be trusted for critical decisions

4. **Service Detection**
   - Limited to implemented protocols
   - May fail if service customized
   - No deep protocol analysis

## Testing Strategy

### Unit Tests

**Coverage**:
- Input parsing and validation (utils)
- Port range parsing
- Data structure creation
- Error handling

**Approach**:
- Pytest framework
- Test edge cases
- Validate error conditions
- Test against localhost (safe)

**Limitations**:
- Can't fully test network features
- No integration tests requiring network
- No permission to scan external hosts

### Manual Testing Checklist

1. Scan localhost
2. Scan local network (with permission)
3. Test all output formats
4. Test error conditions
5. Test with/without privileges
6. Performance testing with different worker counts

## Future Enhancements

### Possible Additions

1. **IPv6 Support**
   - Currently IPv4 only
   - Relatively easy to add

2. **More Output Formats**
   - HTML reports
   - CSV export
   - XML format

3. **Database Storage**
   - Store scan history
   - Compare scans over time
   - Track changes

4. **Configuration Files**
   - Save common scan profiles
   - Avoid repeating CLI arguments

5. **Plugin System**
   - Allow custom service detectors
   - Extensible architecture

6. **Improved OS Fingerprinting**
   - Optional Scapy integration
   - More TCP stack characteristics
   - Better accuracy

7. **Rate Limiting**
   - Adaptive rate control
   - Respect target capacity
   - Bandwidth limiting

8. **Resumable Scans**
   - Save progress
   - Resume interrupted scans
   - Handle large networks better

### Won't Implement

- Exploitation features
- Stealth/evasion techniques
- Brute force capabilities
- Automated vulnerability assessment
- Anything that could be misused for unauthorized access

## Conclusion

This network scanner is designed as a professional, ethical tool for authorized security assessment. The architecture prioritizes:

1. **Safety**: No exploitation, clear warnings
2. **Portability**: Standard library, Python 3.11+
3. **Usability**: Clear CLI, good defaults
4. **Maintainability**: Modular design, type hints
5. **Ethics**: Authorized use only

The limitations are acknowledged and documented. For advanced features requiring root privileges or external libraries, users should consider established tools like nmap, but this implementation provides a solid, understandable, and ethical foundation for network scanning in authorized contexts.
