import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.time import utc_now
from app.models.entities import CollectionRun, IOC, ThreatNews
from app.services.cve_detail import build_nvd_payload
from collector.collector import (
    _cvss,
    _fetch_phishdestroy_domains,
    _parse_alienvault_ips,
    _parse_feodo_ips,
    _parse_malwarebazaar_hashes,
    _parse_openphish_urls,
    _parse_phishdestroy_text,
    _previous_source_statuses,
    _prune_old_data,
    _utc_naive,
    _vendor_product,
    collect_news,
    run_collection,
)


class CollectorParsingTests(unittest.TestCase):
    def test_news_collection_continues_when_one_feed_fails(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine, tables=[ThreatNews.__table__])

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "broken.example":
                return httpx.Response(503, request=request)
            return httpx.Response(
                200,
                request=request,
                text=(
                    "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>"
                    "<item><title>New security advisory</title>"
                    "<link>https://news.example/advisory</link>"
                    "<pubDate>Wed, 08 Jul 2026 12:00:00 GMT</pubDate>"
                    "<description>Patch is available.</description></item>"
                    "</channel></rss>"
                ),
            )

        feeds = {
            "Broken Feed": "https://broken.example/feed.xml",
            "Working Feed": "https://working.example/feed.xml",
        }
        with (
            Session(engine) as db,
            httpx.Client(transport=httpx.MockTransport(handler)) as client,
            patch("collector.collector.RSS_FEEDS", feeds),
            patch("collector.collector.time.sleep"),
        ):
            count, source_counts, source_errors = collect_news(db, client)
            stored = db.scalars(select(ThreatNews)).all()

        self.assertEqual(count, 1)
        self.assertEqual(source_counts, {"Working Feed": 1})
        self.assertIn("Broken Feed", source_errors)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].source, "Working Feed")

    def test_extracts_cvss_v31(self) -> None:
        score, severity = _cvss(
            {
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                }
            }
        )

        self.assertEqual(score, 9.8)
        self.assertEqual(severity, "Critical")

    def test_extracts_vendor_and_product_from_nested_cpe(self) -> None:
        vendor, product = _vendor_product(
            {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": (
                                            "cpe:2.3:a:example_vendor:secure_product:1.0:"
                                            "*:*:*:*:*:*:*"
                                        )
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        )

        self.assertEqual(vendor, "Example Vendor")
        self.assertEqual(product, "Secure Product")

    def test_converts_aware_timestamp_to_naive_utc(self) -> None:
        parsed = _utc_naive("2026-06-27T08:00:00+07:00")

        self.assertEqual(parsed, datetime(2026, 6, 27, 1, 0, 0))
        self.assertIsNone(parsed.tzinfo)

    def test_builds_cve_detail_from_nvd_payload(self) -> None:
        payload = build_nvd_payload(
            {
                "descriptions": [{"lang": "en", "value": "Remote code execution."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "exploitabilityScore": 3.9,
                            "impactScore": 5.9,
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                            },
                        }
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:example:secure_app:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "2.0",
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://vendor.example/advisory",
                        "source": "vendor",
                        "tags": ["Vendor Advisory"],
                    }
                ],
            }
        )

        self.assertEqual(payload["cvss"]["base_score"], 9.8)
        self.assertEqual(payload["cvss"]["attack_vector"], "Network")
        self.assertEqual(payload["affected_products"][0]["product"], "Secure App")
        self.assertEqual(payload["affected_products"][0]["version_range"], "< 2.0")
        self.assertEqual(payload["weaknesses"], ["CWE-78"])

    def test_parses_and_validates_feodo_ips(self) -> None:
        parsed = _parse_feodo_ips(
            "# DstIP\n192.0.2.10\nnot-an-ip\n2001:db8::1\n192.0.2.10\n"
        )

        self.assertEqual(parsed, ["192.0.2.10", "2001:db8::1"])

    def test_parses_and_validates_openphish_urls(self) -> None:
        parsed = _parse_openphish_urls(
            "https://example.test/login\njavascript:alert(1)\n"
            "http://phishing.test/path\nhttps://example.test/login\n"
        )

        self.assertEqual(
            parsed,
            ["https://example.test/login", "http://phishing.test/path"],
        )

    def test_parses_alienvault_reputation_ips(self) -> None:
        parsed = _parse_alienvault_ips(
            "# AlienVault IP Reputation Database\n"
            "49.143.32.6 # Malicious Host KR\n"
            "invalid # Malicious Host\n"
            "2001:db8::5 # Malicious Host\n"
        )

        self.assertEqual(parsed, ["49.143.32.6", "2001:db8::5"])

    def test_parses_malwarebazaar_sha256_and_signature(self) -> None:
        payload = (
            "# MalwareBazaar recent malware samples\n"
            '# "first_seen_utc","sha256_hash","signature"\n'
            '"2026-07-03 06:22:50",'
            '"9a6a6eea504efed17d84a12d67a857268213a8d7d6b92b9fb380b14cf3bb48c9",'
            '"ExampleLoader"\n'
            '"2026-07-03 06:20:00","invalid","n/a"\n'
        )

        parsed = _parse_malwarebazaar_hashes(payload)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["threat"], "ExampleLoader")
        self.assertEqual(
            parsed[0]["indicator"],
            "9a6a6eea504efed17d84a12d67a857268213a8d7d6b92b9fb380b14cf3bb48c9",
        )

    def test_collection_returns_without_work_when_lock_is_held(self) -> None:
        with (
            patch("collector.collector._acquire_collection_lock", return_value=False),
            patch("collector.collector._run_collection_locked") as collect,
        ):
            result = run_collection(object())

        self.assertEqual(result["status"], "already_running")
        collect.assert_not_called()

    def test_parses_phishdestroy_text_and_rejects_invalid_domains(self) -> None:
        parsed = _parse_phishdestroy_text(
            "# generated feed\n"
            "Login.Example.test\n"
            "invalid domain\n"
            "-invalid.example\n"
            "login.example.test\n"
        )

        self.assertEqual(parsed, ["login.example.test"])

    def test_phishdestroy_uses_official_github_fallback_on_api_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "api.destroy.tools":
                return httpx.Response(
                    500,
                    request=request,
                    json={
                        "error": "Internal error",
                        "detail": "KV put() limit exceeded for the day.",
                    },
                )
            return httpx.Response(
                200,
                request=request,
                text="# primary active\none.example\ntwo.example\n",
            )

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            domains, source = _fetch_phishdestroy_domains(client)

        self.assertEqual(domains, ["one.example", "two.example"])
        self.assertEqual(source, "github_fallback")

    def test_prunes_old_news_iocs_and_collection_runs_with_min_keep(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(
            engine,
            tables=[ThreatNews.__table__, IOC.__table__, CollectionRun.__table__],
        )
        now = utc_now()
        old = now - timedelta(days=40)

        with (
            patch("collector.collector.settings.news_retention_days", 30),
            patch("collector.collector.settings.ioc_retention_days", 30),
            patch("collector.collector.settings.collection_run_retention_days", 30),
            patch("collector.collector.settings.collection_run_min_keep", 2),
            Session(engine) as db,
        ):
            db.add_all(
                [
                    ThreatNews(
                        title="old",
                        url="https://old.example",
                        source="test",
                        published_at=old,
                        summary="",
                    ),
                    ThreatNews(
                        title="new",
                        url="https://new.example",
                        source="test",
                        published_at=now,
                        summary="",
                    ),
                    IOC(
                        indicator="old.example",
                        type="domain",
                        threat="",
                        severity="High",
                        source="test",
                        first_seen=old,
                        last_seen=old,
                    ),
                    IOC(
                        indicator="new.example",
                        type="domain",
                        threat="",
                        severity="High",
                        source="test",
                        first_seen=now,
                        last_seen=now,
                    ),
                ]
            )
            for index in range(4):
                db.add(
                    CollectionRun(
                        started_at=old + timedelta(minutes=index),
                        finished_at=old + timedelta(minutes=index),
                        status="success",
                        details="{}",
                    )
                )
            current_run = CollectionRun(
                started_at=now,
                finished_at=now,
                status="running",
                details="{}",
            )
            db.add(current_run)
            db.commit()

            pruned = _prune_old_data(db, current_run.id)

            self.assertEqual(pruned["pruned_news"], 1)
            self.assertEqual(pruned["pruned_iocs"], 1)
            self.assertEqual(pruned["pruned_collection_runs"], 3)
            self.assertEqual(db.scalars(select(ThreatNews.title)).all(), ["new"])
            self.assertEqual(db.scalars(select(IOC.indicator)).all(), ["new.example"])
            self.assertEqual(len(db.scalars(select(CollectionRun.id)).all()), 2)

    def test_previous_source_statuses_reads_latest_prior_run(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine, tables=[CollectionRun.__table__])
        now = utc_now()

        with Session(engine) as db:
            db.add(
                CollectionRun(
                    started_at=now - timedelta(hours=2),
                    finished_at=now - timedelta(hours=2),
                    status="partial",
                    details=json.dumps({"sources": [{"id": "nvd", "status": "ok"}]}),
                )
            )
            db.add(
                CollectionRun(
                    started_at=now - timedelta(hours=1),
                    finished_at=now - timedelta(hours=1),
                    status="partial",
                    details=json.dumps(
                        {
                            "sources": [
                                {"id": "nvd", "status": "error"},
                                {"id": "phishdestroy", "status": "ok"},
                            ]
                        }
                    ),
                )
            )
            current = CollectionRun(started_at=now, finished_at=now, status="running", details="{}")
            db.add(current)
            db.commit()

            self.assertEqual(
                _previous_source_statuses(db, current.id),
                {"nvd": "error", "phishdestroy": "ok"},
            )


if __name__ == "__main__":
    unittest.main()
