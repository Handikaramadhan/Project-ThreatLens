import unittest

from app.services.web_remediation import build_web_remediation


class WebRemediationTests(unittest.TestCase):
    def test_combines_cna_solutions_workarounds_and_github_patches(self) -> None:
        result = build_web_remediation(
            "CVE-2099-0001",
            {
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "example-cna"},
                        "affected": [
                            {
                                "vendor": "Example Corp",
                                "product": "Secure App",
                                "versions": [
                                    {
                                        "version": "1.0",
                                        "lessThan": "2.0",
                                        "versionType": "semver",
                                        "status": "affected",
                                    }
                                ],
                            }
                        ],
                        "solutions": [{"lang": "en", "value": "Install vendor update 2.0."}],
                        "workarounds": [{"lang": "en", "value": "Disable the affected service."}],
                        "references": [
                            {
                                "url": "https://vendor.example/advisory",
                                "tags": ["vendor-advisory"],
                            }
                        ],
                    }
                }
            },
            [
                {
                    "ghsa_id": "GHSA-1234-5678-9012",
                    "html_url": "https://github.com/advisories/GHSA-1234-5678-9012",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "pip", "name": "secure-app"},
                            "patched_versions": "2.0.0",
                        }
                    ],
                }
            ],
        )

        self.assertEqual(result["mitigations"][0]["text"], "Install vendor update 2.0.")
        self.assertIn("secure-app", result["mitigations"][1]["text"])
        self.assertEqual(result["workarounds"][0]["text"], "Disable the affected service.")
        self.assertEqual(len(result["sources"]), 3)
        self.assertEqual(result["affected_products"][0]["vendor"], "Example Corp")
        self.assertEqual(result["affected_products"][0]["product"], "Secure App")
        self.assertEqual(result["affected_products"][0]["version_range"], "< 2.0, semver")


if __name__ == "__main__":
    unittest.main()
