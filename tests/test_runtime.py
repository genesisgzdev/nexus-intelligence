import json
import logging
import socket

import pytest

from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator
from nexus_intelligence.analysis.intelligence.integrity import VectorIntegrityAuditor
from nexus_intelligence.analysis.mail import MailIntelligence
from nexus_intelligence.analysis.subdomains import SubdomainDiscovery
from nexus_intelligence.analysis.web import pinned_http_request
from nexus_intelligence.core.persistence import PersistenceManager
from nexus_intelligence.core.orchestrator import IntelligenceOrchestrator
from nexus_intelligence.core.security import SecurityValidator
from nexus_intelligence.core.reporting import ReportingEngine


LOGGER = logging.getLogger("nexus-tests")


def test_security_validator_rejects_any_private_dns_answer(monkeypatch):
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: answers)

    assert SecurityValidator.is_safe_target("mixed.example") is False


def test_security_validator_accepts_public_dns_answers(monkeypatch):
    answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: answers)

    assert SecurityValidator.is_safe_target("public.example") is True


def test_http_transport_pins_validated_ip_and_preserves_host(monkeypatch):
    observed = []

    def resolve(host):
        observed.append(host)
        return ["203.0.113.8"]

    monkeypatch.setattr(SecurityValidator, "resolve_public_addresses", resolve)
    url, host = pinned_http_request("https://public.example/path?q=1")

    assert url == "https://203.0.113.8/path?q=1"
    assert host == "public.example"
    assert observed == ["public.example"]


def test_reporting_uses_private_safe_filename_and_escapes_markup(tmp_path):
    path = ReportingEngine(str(tmp_path)).generate_markdown(
        "../../<script>alert(1)</script>",
        {"web": {"banner": "```\n<script>alert(2)</script>"}},
    )
    report = open(path, encoding="utf-8").read()
    assert path.startswith(str(tmp_path))
    assert "<script>" not in report
    assert "alert(2)" in report


class StaticConfig:
    timeout = 1
    dns_resolvers = ["127.0.0.1"]
    max_concurrent = 3


@pytest.mark.asyncio
async def test_mail_runtime_uses_self_and_separates_spf_and_dmarc(monkeypatch):
    module = MailIntelligence("example.test", StaticConfig(), LOGGER)
    calls = []

    async def mx_records():
        return ["mx.example.test"]

    async def policy(record_type):
        calls.append(record_type)
        return record_type

    async def banner(_host):
        return "220 test"

    monkeypatch.setattr(module, "get_mx_records", mx_records)
    monkeypatch.setattr(module, "check_policy", policy)
    monkeypatch.setattr(module, "grab_smtp_banner", banner)

    result = await module.run()

    assert result["mx_records"] == ["mx.example.test"]
    assert result["spf_record"] == "SPF"
    assert result["dmarc_record"] == "DMARC"
    assert calls == ["SPF", "DMARC"]
    assert result["banners"] == {"mx.example.test": "220 test"}


@pytest.mark.asyncio
async def test_mail_dmarc_policy_queries_dmarc_subdomain(monkeypatch):
    module = MailIntelligence("example.test", StaticConfig(), LOGGER)
    observed = []

    class Resolver:
        async def resolve(self, target, record_type):
            observed.append((target, record_type))
            return ["v=DMARC1; p=none"]

    monkeypatch.setattr("nexus_intelligence.analysis.mail.dns.asyncresolver.Resolver", Resolver)

    assert await module.check_policy("DMARC") == "v=DMARC1; p=none"
    assert observed == [("_dmarc.example.test", "TXT")]


@pytest.mark.asyncio
async def test_subdomain_wildcard_probe_uses_imported_uuid(monkeypatch):
    module = SubdomainDiscovery("example.test", StaticConfig(), LOGGER)
    observed = []

    class Resolver:
        async def resolve(self, name, record_type):
            observed.append((name, record_type))
            raise RuntimeError("NXDOMAIN")

    monkeypatch.setattr("nexus_intelligence.analysis.subdomains.dns.asyncresolver.Resolver", Resolver)

    assert await module._is_wildcard() is False
    assert observed and observed[0][0].startswith("nexus-wildcard-check-")


@pytest.mark.asyncio
async def test_subdomain_resolver_uses_configured_concurrency_cap(monkeypatch):
    module = SubdomainDiscovery("example.test", StaticConfig(), LOGGER)
    observed = []

    async def resolve(_self, name, record_type):
        observed.append(name)
        return ["203.0.113.10"]

    async def no_wildcard():
        return False

    monkeypatch.setattr(module, "_is_wildcard", no_wildcard)
    monkeypatch.setattr("nexus_intelligence.analysis.subdomains.dns.asyncresolver.Resolver", lambda: type(
        "Resolver", (), {"resolve": resolve}
    )())

    result = await module.run()
    assert result["found_count"] == len(module.BASE_WORDS)
    assert observed


@pytest.mark.asyncio
async def test_persistence_round_trip_feeds_correlator(tmp_path):
    db = PersistenceManager(str(tmp_path / "findings.sqlite3"))
    await db.initialize()
    await db.save_finding("example.test", "DNSIntelligence", {"A": ["192.0.2.10"]})

    findings = await db.get_all_findings()
    correlator = VectorCorrelator()
    correlator.ingest_nexus_results(findings)

    assert findings[0]["target"] == "example.test"
    assert findings[0]["data"] == {"A": ["192.0.2.10"]}
    assert correlator.metadata[0]["source"] == "NEXUS"
    assert correlator.find_related_threats("DNS example test")


def test_tfidf_integrity_audits_actual_matrix():
    correlator = VectorCorrelator()
    correlator.ingest_nexus_results(
        [
            {"target": "alpha.test", "module": "dns", "data": {"record": "alpha"}},
            {"target": "bravo.test", "module": "mail", "data": {"record": "bravo"}},
        ]
    )

    audit = VectorIntegrityAuditor(correlator).audit_index()

    assert audit["vectorizer"] == "tfidf"
    assert audit["index_size"] == 2
    assert audit["is_healthy"] is True


def test_edr_ingestion_skips_malformed_json(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({"category": "network", "description": "C2", "ioc": "203.0.113.7"})
        + "\nnot-json\n",
        encoding="utf-8",
    )
    correlator = VectorCorrelator()

    correlator.ingest_edr_logs(str(path))

    assert len(correlator.metadata) == 1


@pytest.mark.asyncio
async def test_bulk_orchestrator_uses_queued_target_and_persists(monkeypatch, tmp_path):
    class FakeEngine:
        config = StaticConfig()

        def __init__(self, target, config, logger):
            self.target = target
            self.config = config

        async def run(self, modules):
            return {"DNSIntelligence": {"target_seen": self.target}}

    class Reporter:
        def generate_markdown(self, target, results):
            return str(tmp_path / f"{target}.md")

    class Persistence:
        def __init__(self):
            self.saved = []

        async def save_finding(self, target, module, data):
            self.saved.append((target, module, data))

    monkeypatch.setattr("nexus_intelligence.core.orchestrator.IntelligenceEngine", FakeEngine)
    persistence = Persistence()
    orchestrator = IntelligenceOrchestrator(FakeEngine("", StaticConfig(), LOGGER), Reporter(), LOGGER, persistence)
    await orchestrator.add_targets(["alpha.test"])
    await orchestrator.run_parallel(1)

    assert persistence.saved == [("alpha.test", "DNSIntelligence", {"target_seen": "alpha.test"})]
