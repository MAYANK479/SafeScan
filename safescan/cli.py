"""
SafeScan CLI Interface.
Command-line runner for interactive URL safety assessments.
Usage:
    python -m safescan.cli https://example.com
"""

import sys
from .pipeline import SafeScanPipeline


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m safescan.cli <target_url>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"\n[SafeScan AI] Initiating multi-agent scan on: {url}...")
    pipeline = SafeScanPipeline()
    report = pipeline.scan(url)
    report.print_terminal_card()


if __name__ == "__main__":
    main()
