import argparse
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import Config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.analysis.dns import DNSIntelligence
from nexus_intelligence.analysis.ssl import SSLForensics
from nexus_intelligence.analysis.web import WebIntelligence
from nexus_intelligence.analysis.intelligence.math_forensics import BenfordAnalyzer
from rich.console import Console

def main():
    parser = argparse.ArgumentParser(description="Nexus Intelligence v3.1")
    parser.add_argument("target")
    args = parser.parse_args()
    
    logger = setup_logger()
    config = Config()
    engine = IntelligenceEngine(args.target, config, logger)
    
    data = engine.run([DNSIntelligence, SSLForensics, WebIntelligence])
    
    # Cross-module mathematical audit
    all_record_lengths = []
    if 'DNSIntelligence' in data:
        for rtype in ['A', 'MX', 'NS', 'TXT']:
            if rtype in data['DNSIntelligence']:
                all_record_lengths.extend([float(len(r)) for r in data['DNSIntelligence'][rtype]])
    
    if all_record_lengths:
        data['StatisticalAudit'] = BenfordAnalyzer.compute(all_record_lengths)
    
    console = Console()
    console.print(f"\n[bold blue]=== Nexus Intelligence Forensics: {args.target} ===[/]\n")
    for mod, res in data.items():
        console.print(f"[bold cyan]>> {mod}[/]")
        console.print(res)
        console.print("-" * 40)

if __name__ == "__main__": main()
