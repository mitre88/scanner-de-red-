# Network Scanner - Usage Examples

This document provides practical examples for using the network scanner in various scenarios.

## Basic Examples

### 1. Quick Scan of a Single Host
```bash
python main.py --targets 192.168.1.10
```
Scans common ports on a single host.

### 2. Scan a Subnet
```bash
python main.py --targets 192.168.1.0/24
```
Discovers and scans all hosts in a /24 network.

### 3. Scan Specific Ports
```bash
python main.py --targets 192.168.1.10 --ports 22,80,443,3306,5432
```
Scans only the specified ports.

### 4. Scan a Port Range
```bash
python main.py --targets 192.168.1.10 --ports 1-1024
```
Scans all ports from 1 to 1024.

## Advanced Examples

### 5. Full Featured Scan
```bash
python main.py --targets 192.168.1.0/24 \
  --ports 1-1024 \
  --udp \
  --detect-services \
  --os-fingerprint \
  --verbose \
  --output-format json \
  --output-file scan_results.json
```
Comprehensive scan with all features enabled.

### 6. Fast Scan (Internal Network)
```bash
python main.py --targets 10.0.0.0/24 \
  --ports common \
  --timeout 0.5 \
  --workers 200 \
  --no-discovery
```
Optimized for speed on internal networks.

### 7. Deep Scan (Few Hosts)
```bash
python main.py --targets 192.168.1.10,192.168.1.20 \
  --ports 1-65535 \
  --timeout 3.0 \
  --workers 50 \
  --detect-services \
  --os-fingerprint \
  --verbose
```
Thorough scan of specific hosts.

### 8. UDP Service Discovery
```bash
python main.py --targets 192.168.1.0/24 \
  --udp \
  --udp-ports 53,123,161,162 \
  --timeout 2.0
```
Focus on UDP services.

### 9. Web Services Scan
```bash
python main.py --targets 192.168.1.0/24 \
  --ports 80,443,8080,8443 \
  --detect-services \
  --verbose
```
Scan for web services with version detection.

### 10. Database Services Scan
```bash
python main.py --targets 192.168.1.0/24 \
  --ports 3306,5432,1433,27017,6379 \
  --detect-services
```
Identify database services.

## Output Examples

### Text Output (Default)
```bash
python main.py --targets 192.168.1.10 --ports 22,80,443
```

Expected output:
```
======================================================================
Network Scanner Report
======================================================================

Scan Date: 2024-01-15T10:30:45.123456
Scan Duration: 2.45s
Targets Scanned: 1
Hosts Up: 1

Scan Parameters:
  TCP Ports: 22,80,443
  Timeout: 2.0s
  Workers: 100

----------------------------------------------------------------------
Host: 192.168.1.10
----------------------------------------------------------------------
Status: UP
RTT: 1.23ms
Discovery Method: icmp

Open TCP Ports (3):
PORT     STATE       SERVICE         VERSION
22       open        ssh             OpenSSH_8.2p1
80       open        http            nginx/1.18.0
443      open        https           TLSv1.3

======================================================================
Scan Complete
======================================================================
```

### JSON Output
```bash
python main.py --targets 192.168.1.10 --ports 22,80 --output-format json
```

Expected output:
```json
{
  "metadata": {
    "scan_date": "2024-01-15T10:30:45.123456",
    "total_duration": "2.45s",
    "total_targets": 1,
    "hosts_up": 1
  },
  "scan_parameters": {
    "targets": "192.168.1.10",
    "ports": "22,80",
    "udp_enabled": false,
    "timeout": 2.0,
    "workers": 100,
    "detect_services": false,
    "os_fingerprint": false
  },
  "hosts": [
    {
      "ip": "192.168.1.10",
      "status": {
        "is_alive": true,
        "rtt": 1.23,
        "method": "icmp",
        "timestamp": "2024-01-15T10:30:45.123456"
      },
      "scan_results": {
        "tcp": {
          "ports": [
            {
              "port": 22,
              "state": "open",
              "service": "ssh",
              "timestamp": "2024-01-15T10:30:46.123456"
            },
            {
              "port": 80,
              "state": "open",
              "service": "http",
              "timestamp": "2024-01-15T10:30:46.223456"
            }
          ],
          "scan_duration": 1.5
        }
      }
    }
  ]
}
```

## Performance Tuning

### For Large Networks
```bash
# Increase workers, reduce timeout
python main.py --targets 10.0.0.0/16 \
  --ports common \
  --timeout 0.5 \
  --workers 500 \
  --no-discovery
```

### For Slow Networks
```bash
# Increase timeout, reduce workers
python main.py --targets 192.168.1.0/24 \
  --ports common \
  --timeout 5.0 \
  --workers 20
```

### For Detailed Analysis
```bash
# Lower concurrency, enable all features
python main.py --targets 192.168.1.10 \
  --ports 1-65535 \
  --timeout 3.0 \
  --workers 50 \
  --detect-services \
  --os-fingerprint \
  --verbose
```

## Common Scenarios

### Internal Network Audit
```bash
python main.py --targets 10.0.0.0/24 \
  --ports 22,80,443,445,3389,5900 \
  --detect-services \
  --output-format json \
  --output-file audit_$(date +%Y%m%d).json
```

### Web Server Discovery
```bash
python main.py --targets 192.168.1.0/24 \
  --ports 80,443,8000-8100 \
  --detect-services \
  --verbose
```

### Service Version Enumeration
```bash
python main.py --targets 192.168.1.10-192.168.1.20 \
  --ports common \
  --detect-services \
  --verbose \
  --output-file service_versions.txt
```

### OS Fingerprinting
```bash
python main.py --targets 192.168.1.0/24 \
  --ports 22,80,443 \
  --os-fingerprint \
  --output-format json \
  --output-file os_inventory.json
```

## Troubleshooting Examples

### Test Connectivity First
```bash
# Simple connectivity test
python main.py --targets 192.168.1.1 --ports 80 --timeout 1.0
```

### Debug Mode
```bash
# Enable detailed logging
python main.py --targets 192.168.1.10 \
  --ports 22,80 \
  --verbose \
  --log-level DEBUG
```

### Test Without ICMP
```bash
# Force TCP-based discovery
python main.py --targets 192.168.1.10 \
  --no-discovery \
  --ports 22,80,443
```

## Integration Examples

### Parse JSON with jq
```bash
# Get list of hosts with open port 22
python main.py --targets 192.168.1.0/24 \
  --ports 22 \
  --output-format json \
  --quiet | jq -r '.hosts[] | select(.scan_results.tcp.ports[] | select(.port==22 and .state=="open")) | .ip'
```

### Export to CSV
```bash
# Extract open ports to CSV
python main.py --targets 192.168.1.0/24 \
  --ports common \
  --output-format json \
  --quiet | jq -r '.hosts[] | .scan_results.tcp.ports[] | [.port, .state, .service] | @csv'
```

### Continuous Monitoring
```bash
#!/bin/bash
# Run scan every hour and save results
while true; do
  python main.py --targets 192.168.1.0/24 \
    --ports common \
    --output-format json \
    --output-file "scan_$(date +%Y%m%d_%H%M%S).json" \
    --quiet
  sleep 3600
done
```

## Best Practices

1. **Always get authorization** before scanning
2. **Start with small scans** to test configuration
3. **Use appropriate timeouts** for your network
4. **Save results** for documentation and comparison
5. **Respect rate limits** - don't overwhelm systems
6. **Document your scans** - keep logs of what you scan and when

## Error Handling

### Handle Timeout Errors
```bash
# Increase timeout if getting many timeouts
python main.py --targets 192.168.1.0/24 --timeout 5.0
```

### Handle Permission Errors
```bash
# If ICMP fails, scanner automatically falls back to TCP
# Or explicitly skip discovery:
python main.py --targets 192.168.1.10 --no-discovery
```

### Handle Large Networks
```bash
# Break large networks into smaller chunks
for subnet in 10.0.{0..255}.0/24; do
  python main.py --targets $subnet --ports common --output-file "scan_$subnet.json"
done
```

## Notes

- All scans should be performed on networks you have authorization to scan
- Results may vary based on firewalls, IDS/IPS, and network conditions
- UDP scanning is inherently less reliable than TCP scanning
- Service detection accuracy depends on service configuration
- OS fingerprinting provides best-effort guesses, not definitive identification

For more information, see README.md and DESIGN_NOTES.md
