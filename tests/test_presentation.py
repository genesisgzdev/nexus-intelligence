import logging
import sys

import pytest

from nexus_intelligence import __main__ as cli
from nexus_intelligence.core.presentation import describe
from nexus_intelligence.core.reporting import ReportingEngine


def test_certificate_reading_does_not_claim_verification():
    message = describe('SSLForensics', {'certificate_verified': False})
    assert 'no está verificada' in message


def test_report_explains_partial_results_and_preserves_escaped_evidence(tmp_path):
    results = {'WebIntelligence': {'status_code': 503, 'title': '<script>bad()</script>'},
               'SSLForensics': {'error': 'timeout'}}
    report = ReportingEngine(str(tmp_path)).generate_markdown('example.test', results)
    text = open(report, encoding='utf-8').read()
    assert '1 de 2 consultas' in text
    assert 'Revisa el acceso' in text
    assert '<script>' not in text
    assert '503' in text and 'timeout' in text
    assert '<details>' in text


@pytest.mark.asyncio
async def test_comments_only_file_is_not_reported_as_success(monkeypatch, tmp_path):
    path = tmp_path / 'domains.txt'
    path.write_text('# No domains yet\n\n')
    monkeypatch.setattr(sys, 'argv', ['nexus-intel', '--file', str(path)])
    monkeypatch.setattr(cli, 'setup_logger', lambda *a, **kw: logging.getLogger('test'))
    assert await cli.entrypoint() == 2


def test_concurrency_outside_configured_capacity_is_not_silently_reduced():
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        cli._validate_args(parser.parse_args(['--file', 'domains.txt', '--concurrency', '0']), parser)
