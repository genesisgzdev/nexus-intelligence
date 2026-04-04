import argparse
import sys
from typing import List, Dict, Any
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.analysis.dns import DNSIntelligence
from nexus_intelligence.analysis.ssl import SSLForensics
from nexus_intelligence.analysis.web import WebIntelligence
from nexus_intelligence.analysis.intelligence.math_forensics import BenfordAnalyzer, MarkovChain
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

def main():
    parser = argparse.ArgumentParser(description="Nexus Intelligence v3.2 - Advanced OSINT Framework")
    parser.add_argument("target", help="Target domain for forensic analysis")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable detailed logging")
    args = parser.parse_args()
    
    # Initialize Core infrastructure with Pydantic validation
    logger = setup_logger(output_dir=config.output_dir, verbose=args.verbose or config.verbose)
    console = Console()
    
    console.print(Panel.fit(
        f"[bold blue]Nexus Intelligence Framework[/]\n[cyan]Target:[/] {args.target}\n[cyan]OPSEC:[/] DoH + TLS Impersonation Active",
        title="v3.2.0 (Forensic Edition)",
        border_style="blue"
    ))
    
    engine = IntelligenceEngine(args.target, config, logger)
    
    # Execution Phase
    modules = [DNSIntelligence, SSLForensics, WebIntelligence]
    data = engine.run(modules)
    
    # Cross-module mathematical forensic audit
    all_record_lengths: List[float] = []
    if 'DNSIntelligence' in data:
        dns_data = data['DNSIntelligence']
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            if rtype in dns_data:
                all_record_lengths.extend([float(len(str(r))) for r in dns_data[rtype]])
    
    if all_record_lengths:
        data['StatisticalAudit'] = BenfordAnalyzer.compute(all_record_lengths)
    
    # Markovian determinism check on target domain
    data['DeterministicProfile'] = MarkovChain.analyze(args.target)
    
    # Visualization Phase
    for mod, res in data.items():
        console.print(f"\n[bold cyan]─── {mod} ───[/]")
        if "error" in res:
            console.print(f"[bold red]![/] {res['error']}")
        else:
            # We skip detailed internal data if too large for console
            console.print_json(data=res)

    console.print(f"\n[bold green]✔ Analysis Complete.[/] Logs persisted in [white]{config.output_dir}/[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(130)
