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
    v_correlator.ingest_nexus_results(await db.get_all_findings())

    correlation_matches = v_correlator.find_related_threats(f"Findings for {target}")
    if correlation_matches:
        logger.info(f"Cross-project correlation identified {len(correlation_matches)} relevant matches.")

    # Mathematical Verification
    v_auditor = VectorIntegrityAuditor(v_correlator)
    if not v_auditor.audit_index().get("is_healthy"):
        logger.warning("Vector index drift detected. Search precision may be compromised.")

def _build_parser() -> argparse.ArgumentParser:
    cli_parser = argparse.ArgumentParser(description="Nexus Intelligence: Asynchronous OSINT Runtime")
    cli_parser.add_argument("target", nargs="?", help="Target domain or IP")
    cli_parser.add_argument("--file", help="Source file for bulk target ingestion")
    cli_parser.add_argument("--concurrency", type=int, default=5, help="Async worker pool size for --file (1-NEXUS_MAX_CONCURRENT)")
    cli_parser.add_argument("--correlate", action="store_true", help="Write a cross-target TF-IDF correlation summary after --file")
    return cli_parser


def _validate_args(cmd_args: argparse.Namespace, cli_parser: argparse.ArgumentParser) -> None:
    if cmd_args.file and cmd_args.target:
        cli_parser.error("target and --file are mutually exclusive")
    if cmd_args.correlate and not cmd_args.file:
        cli_parser.error("--correlate requires --file")


async def entrypoint() -> int:
    """
    Application entrypoint for CLI orchestration.
    """
    cli_parser = _build_parser()
    cmd_args = cli_parser.parse_args()
    _validate_args(cmd_args, cli_parser)

    runtime_logger = setup_logger(config.output_dir, verbose=config.verbose)

    if cmd_args.file:
        if not os.path.exists(cmd_args.file):
            runtime_logger.error(f"Configuration Fault: Target file '{cmd_args.file}' not accessible.")
            return 2

        persistence = PersistenceManager()
        await persistence.initialize()
        report_gen = ReportingEngine(config.output_dir)
        
        with open(cmd_args.file, "r") as f:
            target_list = [line.strip() for line in f if line.strip()]
        
        orch_engine = IntelligenceEngine("", config, runtime_logger)
        concurrency = max(1, min(cmd_args.concurrency, config.max_concurrent))
        runtime_orchestrator = IntelligenceOrchestrator(orch_engine, report_gen, runtime_logger, persistence)
        await runtime_orchestrator.add_targets(target_list)
        await runtime_orchestrator.run_parallel(concurrency)

        if cmd_args.correlate:
            correlator = VectorCorrelator()
            edr_log_stream = os.environ.get("TDS_LOG_PATH", "logs/tds_threats.jsonl")
            if os.path.exists(edr_log_stream):
                correlator.ingest_edr_logs(edr_log_stream)
            findings = await persistence.get_all_findings()
            correlator.ingest_nexus_results(findings)
            matches = correlator.find_related_pairs()
            summary = {
                "target_count": len(set(target_list)),
                "finding_count": len(findings),
                "matches": matches,
            }
            artifact = report_gen.generate_batch_summary(summary)
            runtime_logger.info("Bulk correlation artifact generated: %s", artifact)
        return 0
        
    elif cmd_args.target:
        persistence = PersistenceManager()
        await persistence.initialize()
        report_gen = ReportingEngine(config.output_dir)
        core_engine = IntelligenceEngine(cmd_args.target, config, runtime_logger)
        await execute_forensic_pipeline(cmd_args.target, core_engine, report_gen, persistence, runtime_logger)
        return 0
    else:
        cli_parser.print_help()
        return 0


def main():
    """Console-script entry point installed by the package metadata."""
    try:
        return asyncio.run(entrypoint())
    except KeyboardInterrupt:
        return 130

if __name__ == "__main__":
    sys.exit(main())
