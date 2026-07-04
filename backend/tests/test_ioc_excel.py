import unittest
from datetime import datetime
from io import BytesIO
from types import SimpleNamespace
from zipfile import ZipFile

from app.services.ioc_excel import build_ioc_workbook


class IOCExcelTests(unittest.TestCase):
    def test_workbook_contains_summary_and_filtered_indicator_data(self) -> None:
        now = datetime(2026, 7, 3, 8, 30)
        items = [
            SimpleNamespace(
                indicator="203.0.113.8",
                type="ip",
                threat="C2",
                severity="High",
                source="URLhaus",
                first_seen=now,
                last_seen=now,
            ),
            SimpleNamespace(
                indicator="=HYPERLINK(\"https://malicious.test\")",
                type="ip",
                threat="Formula injection test",
                severity="Medium",
                source="Test",
                first_seen=now,
                last_seen=now,
            ),
        ]

        payload = build_ioc_workbook(items, "ip")

        self.assertTrue(payload.startswith(b"PK"))
        with ZipFile(BytesIO(payload)) as archive:
            workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
            indicator_xml = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
            shared_strings = archive.read("xl/sharedStrings.xml").decode("utf-8")

        self.assertIn('name="Summary"', workbook_xml)
        self.assertIn('name="Indicators"', workbook_xml)
        self.assertIn("203.0.113.8", shared_strings)
        self.assertIn("HYPERLINK", shared_strings)
        self.assertNotIn("<f>", indicator_xml)


if __name__ == "__main__":
    unittest.main()
