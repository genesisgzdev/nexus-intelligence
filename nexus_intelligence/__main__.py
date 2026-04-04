"""
Main entry point for the Nexus Intelligence CLI.
"""
import argparse
import sys
import os

# Add package root to sys.path if running as script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_intelligence.core.config import Config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.core.engine import Orchestrator

from nexus_intelligence.analysis.dns import DNSAnalyzer
from nexus_intelligence.analysis.ssl import SSLAnalyzer
from nexus_intelligence.analysis.web import WebAnalyzer

from nexus_intelligence.reporting.json import JSONReporter
from nexus_intelligence.reporting.html import HTMLReporter

def main():
    parser = argparse.ArgumentParser(description="Nexus Intelligence v2.0: Modular OSINT Framework")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("--format", "-f", choices=["json", "html"], default="html", help="Report format")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")
    
    args = parser.parse_args()
    
    logger = setup_logger(verbose=args.verbose)
    config = Config()
    
    orchestrator = Orchestrator(args.target, config, logger)
    
    # Define modules to run
    modules = [DNSAnalyzer, SSLAnalyzer, WebAnalyzer]
    
    results = orchestrator.run_parallel(modules)
    
    # Determine output path
    output_path = args.output
    if not output_path:
        output_path = os.path.join(config.output_dir, f"report_{args.target}.{args.format}")
        
    logger.info(f"Generating [bold cyan]{args.format.upper()}[/] report to: [italic]{output_path}[/]")
    
    if args.format == "json":
        JSONReporter(args.target, results, output_path).generate()
    elif args.format == "html":
        HTMLReporter(args.target, results, output_path).generate()
        
    logger.info("[bold green]Scan completed successfully. Operational intelligence secured.[/]")

if __name__ == "__main__":
    main()
