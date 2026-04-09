import asyncio
import sys
import argparse
import os
import logging
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.core.persistence import PersistenceManager
from nexus_intelligence.core.reporting import ReportingEngine
from nexus_intelligence.core.orchestrator import IntelligenceOrchestrator
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator
from nexus_intelligence.analysis.intelligence.integrity import VectorIntegrityAuditor

async def execute_forensic_pipeline(target: str, engine: IntelligenceEngine, reporting: ReportingEngine, db: PersistenceManager, logger: logging.Logger):
    """
    Orchestrates the full lifecycle of a single target forensic scan.
    """
    from nexus_intelligence.analysis.dns import DNSIntelligence
    from nexus_intelligence.analysis.web import WebIntelligence
    from nexus_intelligence.analysis.ssl import SSLForensics
    from nexus_intelligence.analysis.mail import MailIntelligence
    from nexus_intelligence.analysis.subdomains import SubdomainDiscovery

    active_modules = [DNSIntelligence, WebIntelligence, SSLForensics, MailIntelligence, SubdomainDiscovery]
    execution_results = await engine.run(active_modules)
    
    for module_name, result_data in execution_results.items():
        await db.save_finding(target, module_name, result_data)
    
    report_artifact = reporting.generate_markdown(target, execution_results)
    logger.info(f"Forensic artifact generated: {report_artifact}")

    # Automated Semantic Linkage
    v_correlator = VectorCorrelator()
    edr_log_stream = os.environ.get("TDS_LOG_PATH", "logs/tds_threats.jsonl")
    
    if os.path.exists(edr_log_stream):
        v_correlator.ingest_edr_logs(edr_log_stream)
    
    correlation_matches = v_correlator.find_related_threats(f"Findings for {target}")
    if correlation_matches:
        logger.info(f"Cross-project correlation identified {len(correlation_matches)} relevant matches.")

    # Mathematical Verification
    v_auditor = VectorIntegrityAuditor(v_correlator)
    if not v_auditor.audit_index().get("is_healthy"):
        logger.warning("Vector index drift detected. Search precision may be compromised.")

async def entrypoint():
    """
    Application entrypoint for CLI orchestration.
    """
    cli_parser = argparse.ArgumentParser(description="Nexus Intelligence: Asynchronous OSINT Runtime")
    cli_parser.add_argument("target", nargs="?", help="Target domain or IP")
    cli_parser.add_argument("--file", help="Source file for bulk target ingestion")
    cli_parser.add_argument("--concurrency", type=int, default=5, help="Async worker pool size")
    cmd_args = cli_parser.parse_args()

    runtime_logger = setup_logger(config.verbose)
    persistence = PersistenceManager()
    await persistence.initialize()
    report_gen = ReportingEngine()

    if cmd_args.file:
        if not os.path.exists(cmd_args.file):
            runtime_logger.error(f"Configuration Fault: Target file '{cmd_args.file}' not accessible.")
            return
        
        with open(cmd_args.file, "r") as f:
            target_list = [line.strip() for line in f if line.strip()]
        
        orch_engine = IntelligenceEngine("", config, runtime_logger)
        runtime_orchestrator = IntelligenceOrchestrator(orch_engine, report_gen, runtime_logger)
        await runtime_orchestrator.add_targets(target_list)
        await runtime_orchestrator.run_parallel(cmd_args.concurrency)
        
    elif cmd_args.target:
        core_engine = IntelligenceEngine(cmd_args.target, config, runtime_logger)
        await execute_forensic_pipeline(cmd_args.target, core_engine, report_gen, persistence, runtime_logger)
    else:
        cli_parser.print_help()

if __name__ == "__main__":
    try:
        asyncio.run(entrypoint())
    except KeyboardInterrupt:
        sys.exit(0)
