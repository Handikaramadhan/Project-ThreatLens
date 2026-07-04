import unittest

from app.services.product_resolution import (
    extract_cve_org_products,
    infer_product_from_description,
    is_unknown_product,
)


class ProductResolutionTests(unittest.TestCase):
    def test_extracts_affected_products_from_cna_and_skips_unaffected_versions(self) -> None:
        products = extract_cve_org_products(
            {
                "containers": {
                    "cna": {
                        "affected": [
                            {
                                "vendor": "Acme",
                                "product": "Gateway",
                                "versions": [
                                    {"version": "4.0", "lessThan": "4.8", "status": "affected"},
                                    {"version": "4.8", "status": "unaffected"},
                                ],
                            }
                        ]
                    }
                }
            }
        )

        self.assertEqual(len(products), 1)
        self.assertEqual(products[0]["product"], "Gateway")
        self.assertEqual(products[0]["version_range"], "< 4.8")

    def test_infers_oracle_product_phrase_conservatively(self) -> None:
        result = infer_product_from_description(
            "Vulnerability in the Oracle Payments product of Oracle E-Business Suite "
            "(component: File Transmission)."
        )

        self.assertEqual(result, ("Oracle", "Oracle Payments"))

    def test_unknown_values_are_normalized(self) -> None:
        self.assertTrue(is_unknown_product("N/A"))
        self.assertTrue(is_unknown_product(""))
        self.assertFalse(is_unknown_product("FortiOS"))


if __name__ == "__main__":
    unittest.main()
