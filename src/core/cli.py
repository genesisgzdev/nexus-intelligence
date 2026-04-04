import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Nexus Intelligence: Modular Zero-API Security Analyzer")
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--format", "-f", choices=["json", "csv", "sqlite", "md", "html", "pdf"], default="json", help="Report output format")
    parser.add_argument("--output", "-o", help="Output file path")
    return parser.parse_args()
