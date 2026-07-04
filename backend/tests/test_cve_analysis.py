import unittest

from app.schemas.cves import CVSSMetrics
from app.services.cve_analysis import build_mitre_mapping, build_root_cause


class CVEAnalysisTests(unittest.TestCase):
    def test_root_cause_uses_nvd_cwe_before_description_heuristic(self) -> None:
        result = build_root_cause("A generic vulnerability.", ["CWE-89"])

        self.assertEqual(result.category, "Injection")
        self.assertEqual(result.confidence, "High")
        self.assertEqual(result.weaknesses, ["CWE-89"])

    def test_root_cause_can_infer_common_weakness_from_description(self) -> None:
        result = build_root_cause("A remote path traversal vulnerability.", [])

        self.assertEqual(result.category, "File access control")
        self.assertEqual(result.confidence, "Medium")
        self.assertEqual(result.basis, "Description keyword heuristic")

    def test_network_command_injection_maps_to_defensible_techniques(self) -> None:
        mappings = build_mitre_mapping(
            "A remote attacker can execute commands over HTTP.",
            ["CWE-78"],
            CVSSMetrics(attack_vector="Network", user_interaction="None"),
        )

        self.assertEqual([item.technique_id for item in mappings], ["T1190", "T1059"])


if __name__ == "__main__":
    unittest.main()
