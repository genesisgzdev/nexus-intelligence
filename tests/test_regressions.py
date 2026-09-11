import asyncio
import json
import logging
from pathlib import Path

import pytest

from nexus_intelligence.analysis.intelligence.math_forensics import BenfordAnalyzer
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.reporting import ReportingEngine


@pytest.mark.parametrize('value,digit', [(0.04, 4), (0.0099, 9), (-0.0007, 7), (5e-324, 5), (999., 9)])
def test_first_digit_handles_fractional_and_subnormal_numbers(value, digit):
    assert BenfordAnalyzer.get_first_digit(value) == digit


def test_nonobject_json_lines_do_not_abort_correlation(tmp_path):
    path = tmp_path / 'input.jsonl'
    path.write_text('null\n[]\n42\n'+json.dumps({'category': 'dns', 'description': 'test observation'})+'\n')
    correlator = VectorCorrelator()
    correlator.ingest_edr_logs(str(path))
    assert len(correlator.metadata) == 1


def test_zero_results_limit_is_empty():
    correlator = VectorCorrelator()
    correlator.ingest_nexus_results([{'target': 'alpha.test', 'module': 'dns', 'data': 'record'}])
    assert correlator.find_related_threats('alpha', top_k=0) == []


@pytest.mark.asyncio
async def test_restricted_target_still_produces_structured_report(tmp_path):
    config = type('Config', (), {'timeout': 1})()
    result = await IntelligenceEngine('127.0.0.1', config, logging.getLogger('test')).run([])
    path = ReportingEngine(str(tmp_path)).generate_markdown('127.0.0.1', result)
    assert 'security_violation' in Path(path).read_text()
    assert all(isinstance(value, dict) for value in result.values())


def test_repeated_reports_do_not_overwrite_prior_evidence(tmp_path):
    reporter = ReportingEngine(str(tmp_path))
    first = reporter.generate_markdown('example.test', {'dns': {'value': 1}})
    second = reporter.generate_markdown('example.test', {'dns': {'value': 2}})
    assert first != second
    assert '&quot;value&quot;: 1' in Path(first).read_text()
