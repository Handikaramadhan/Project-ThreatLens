import unittest
from datetime import datetime

from app.services.cve_detail import build_nvd_payload
from collector.collector import (
    _cvss,
    _parse_alienvault_ips,
    _parse_feodo_ips,
    _parse_malwarebazaar_hashes,
    _parse_openphish_urls,
    _utc_naive,
    _vendor_product,
)


class CollectorParsingTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
