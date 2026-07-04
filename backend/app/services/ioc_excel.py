from datetime import datetime
from io import BytesIO

import xlsxwriter

from app.models.entities import IOC

SEVERITY_COLORS = {
    "Critical": ("#FDE8EA", "#B91C1C"),
    "High": ("#FFF0E6", "#C2410C"),
    "Medium": ("#FFF7D6", "#A16207"),
    "Low": ("#E8F8EE", "#15803D"),
    "Unknown": ("#ECEEF2", "#4B5563"),
}


def build_ioc_workbook(items: list[IOC], selected_type: str) -> bytes:
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True, "constant_memory": False})
    workbook.set_properties(
        {
            "title": "ThreatLens Indicator Intelligence Export",
            "subject": f"IOC export filtered by {selected_type}",
            "author": "ThreatLens",
            "company": "ThreatLens",
            "comments": "Generated from the authenticated ThreatLens workspace.",
        }
    )
    title = workbook.add_format(
        {
            "bold": True,
            "font_size": 18,
            "font_color": "#F2F3F5",
            "bg_color": "#121419",
            "align": "left",
            "valign": "vcenter",
        }
    )
    subtitle = workbook.add_format({"font_color": "#686C76", "font_size": 9})
    label = workbook.add_format({"bold": True, "font_color": "#686C76", "font_size": 9})
    value = workbook.add_format({"bold": True, "font_color": "#17191F", "font_size": 11})
    header = workbook.add_format(
        {
            "bold": True,
            "font_color": "#FFFFFF",
            "bg_color": "#17191F",
            "border": 0,
            "align": "left",
            "valign": "vcenter",
        }
    )
    text = workbook.add_format({"font_color": "#292C33", "valign": "top"})
    code = workbook.add_format({"font_name": "Consolas", "font_color": "#17191F", "valign": "top"})
    date_format = workbook.add_format({"num_format": "yyyy-mm-dd hh:mm", "font_color": "#292C33"})

    summary = workbook.add_worksheet("Summary")
    summary.hide_gridlines(2)
    summary.set_column("A:A", 24)
    summary.set_column("B:B", 22)
    summary.set_column("D:D", 18)
    summary.set_column("E:E", 14)
    summary.set_row(0, 34)
    summary.merge_range("A1:E1", "ThreatLens Indicator Intelligence", title)
    summary.write("A3", "Generated", label)
    summary.write_datetime("B3", datetime.utcnow(), date_format)
    summary.write("A4", "Filter", label)
    summary.write_string("B4", selected_type.upper(), value)
    summary.write("A5", "Total indicators", label)
    summary.write_number("B5", len(items), value)

    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for item in items:
        severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
        source_counts[item.source or "Unknown"] = source_counts.get(item.source or "Unknown", 0) + 1
        type_counts[item.type.upper()] = type_counts.get(item.type.upper(), 0) + 1

    summary.write("A8", "Severity", header)
    summary.write("B8", "Count", header)
    for row, severity in enumerate(("Critical", "High", "Medium", "Low", "Unknown"), start=8):
        background, foreground = SEVERITY_COLORS[severity]
        severity_format = workbook.add_format(
            {"bold": True, "bg_color": background, "font_color": foreground}
        )
        summary.write_string(row, 0, severity, severity_format)
        summary.write_number(row, 1, severity_counts.get(severity, 0), text)

    summary.write("D8", "Source", header)
    summary.write("E8", "Count", header)
    for row, (source, count) in enumerate(
        sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[:15],
        start=8,
    ):
        summary.write_string(row, 3, source, text)
        summary.write_number(row, 4, count, text)

    summary.write("A16", "Indicator type", header)
    summary.write("B16", "Count", header)
    for row, (indicator_type, count) in enumerate(sorted(type_counts.items()), start=16):
        summary.write_string(row, 0, indicator_type, text)
        summary.write_number(row, 1, count, text)
    summary.write("A23", "Notes", label)
    summary.merge_range(
        "A24:E25",
        "Treat indicators as investigative leads. Validate scope, freshness, and source confidence before blocking.",
        subtitle,
    )

    sheet = workbook.add_worksheet("Indicators")
    sheet.hide_gridlines(2)
    sheet.freeze_panes(1, 0)
    sheet.set_default_row(20)
    columns = [
        ("Indicator", 54),
        ("Type", 12),
        ("Threat", 30),
        ("Severity", 13),
        ("Source", 24),
        ("First Seen", 20),
        ("Last Seen", 20),
    ]
    for index, (_, width) in enumerate(columns):
        sheet.set_column(index, index, width)
    for column, (name, _) in enumerate(columns):
        sheet.write_string(0, column, name, header)

    for row, item in enumerate(items, start=1):
        background, foreground = SEVERITY_COLORS.get(
            item.severity,
            SEVERITY_COLORS["Unknown"],
        )
        severity_format = workbook.add_format(
            {"bold": True, "bg_color": background, "font_color": foreground}
        )
        sheet.write_string(row, 0, item.indicator, code)
        sheet.write_string(row, 1, item.type.upper(), text)
        sheet.write_string(row, 2, item.threat or "", text)
        sheet.write_string(row, 3, item.severity, severity_format)
        sheet.write_string(row, 4, item.source or "", text)
        sheet.write_datetime(row, 5, item.first_seen, date_format)
        sheet.write_datetime(row, 6, item.last_seen, date_format)

    last_row = max(1, len(items))
    sheet.autofilter(0, 0, last_row, len(columns) - 1)
    sheet.set_row(0, 26)
    workbook.close()
    return output.getvalue()
