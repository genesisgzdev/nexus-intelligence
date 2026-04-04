import sys
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cli import parse_args
from core.config import Config
from core.logger import setup_logger

from modules.dns_analyzer import DNSAnalyzer
from modules.ssl_analyzer import SSLAnalyzer
from modules.web_fingerprint import WebFingerprint

from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter
from reporters.pdf_reporter import PDFReporter

def main():
    args = parse_args()
    logger = setup_logger(args.verbose)
    config = Config()
    
    logger.info(f"Starting Nexus Intelligence scan on {args.target}")
    
    modules = [
        DNSAnalyzer(args.target, config, logger),
        SSLAnalyzer(args.target, config, logger),
        WebFingerprint(args.target, config, logger)
    ]
    
    scan_data = {}
    for mod in modules:
        mod_name = mod.__class__.__name__
        logger.info(f"Executing {mod_name}...")
        scan_data[mod_name] = mod.run()
        
    out_file = args.output
    if not out_file:
        out_file = os.path.join(config.output_dir, f"{args.target}.{args.format}")
        
    logger.info(f"Generating {args.format.upper()} report to {out_file}")
    
    try:
        if args.format == "json":
            JSONReporter(args.target, scan_data, out_file).generate()
        elif args.format == "html":
            HTMLReporter(args.target, scan_data, out_file).generate()
        elif args.format == "pdf":
            PDFReporter(args.target, scan_data, out_file).generate()
        else:
            logger.warning(f"Format {args.format} not fully implemented yet, falling back to JSON")
            JSONReporter(args.target, scan_data, out_file + '.json').generate()
            
        logger.info("Scan completed successfully.")
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")

if __name__ == "__main__":
    main()
