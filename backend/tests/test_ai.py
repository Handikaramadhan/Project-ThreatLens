import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services.ai import AIUnavailable, _extract_json, investigate_cve


class AITests(unittest.TestCase):
    def test_extract_json_accepts_fenced_agent_output(self) -> None:
        payload = _extract_json('```json\n{"executive_summary":"verified"}\n```')

        self.assertEqual(payload["executive_summary"], "verified")

    def test_extract_json_rejects_non_structured_output(self) -> None:
        with self.assertRaises(AIUnavailable):
            _extract_json("No structured result")

    @patch("app.services.ai.run_agent")
    def test_investigation_normalizes_product_confidence(self, run_agent) -> None:
        run_agent.return_value = json.dumps(
            {
                "executive_summary": "Summary",
                "product_inference": {
                    "vendor": "Example",
                    "product": "Gateway",
                    "versions": ["1.0"],
                    "confidence": 4,
                    "evidence": ["Vendor advisory"],
                },
                "attack_path": ["Remote request"],
            }
        )
        cve = SimpleNamespace(
            cve_id="CVE-2026-12345",
            vendor="Unknown",
            product="",
            severity="High",
            cvss_score=8.1,
            description="Example vulnerability",
        )

        payload = investigate_cve(cve, {}, {}, "test-session")

        self.assertEqual(payload["product_inference"]["product"], "Gateway")
        self.assertEqual(payload["product_inference"]["confidence"], 1.0)
        self.assertEqual(payload["mitigation"], [])


if __name__ == "__main__":
    unittest.main()
