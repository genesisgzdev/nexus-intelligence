import json
import logging

import pytest

from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator
from nexus_intelligence.analysis.intelligence.integrity import VectorIntegrityAuditor
from nexus_intelligence.analysis.mail import MailIntelligence
from nexus_intelligence.analysis.subdomains import SubdomainDiscovery
from nexus_intelligence.core.persistence import PersistenceManager


LOGGER = logging.getLogger("nexus-tests")


class StaticConfig:
    timeout = 1
    dns_resolvers = ["127.0.0.1"]


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
