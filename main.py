#!/usr/bin/env python3
"""
Network Scanner - Main Entry Point

Professional-grade network scanner for authorized security assessments.

WARNING: This tool is for authorized use only. Ensure you have explicit
permission before scanning any network or system.

Usage:
    python main.py --targets <target> [options]

For detailed help:
    python main.py --help
"""

from scanner.cli import main

if __name__ == '__main__':
    main()
