from io import BytesIO
from urllib.parse import urlparse
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas.cves import CVEDetailOut

NAVY = colors.HexColor("#0B1F33")
INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#64748B")
CYAN = colors.HexColor("#0891B2")
LINE = colors.HexColor("#D7E0EA")
PALE = colors.HexColor("#F4F7FA")
RED = colors.HexColor("#DC2626")
ORANGE = colors.HexColor("#EA580C")
YELLOW = colors.HexColor("#CA8A04")
GREEN = colors.HexColor("#16A34A")


def _text(value: object) -> str:
    return escape(str(value or "")).replace("\n", "<br/>")


def _link(url: str, label: str) -> str:
    safe_url = escape(url, {'"': "&quot;"})
    return f'<link href="{safe_url}" color="#087E9B">{_text(label)}</link>'


def _source_label(url: str, fallback: str) -> str:
    try:
        return urlparse(url).hostname or fallback
    except ValueError:
        return fallback


def _severity_color(severity: str) -> colors.Color:
    return {
        "critical": RED,
        "high": ORANGE,
        "medium": YELLOW,
        "low": GREEN,
    }.get(severity.lower(), MUTED)


def build_cve_pdf(detail: CVEDetailOut) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=23,
            textColor=NAVY,
            spaceAfter=3 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=NAVY,
            spaceBefore=5 * mm,
            spaceAfter=2.5 * mm,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=INK,
            spaceAfter=1.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableText",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=INK,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableTextMuted",
            parent=styles["TableText"],
            textColor=MUTED,
        )
    )
    styles.add(
        ParagraphStyle(
            name="TableHeader",
            parent=styles["TableText"],
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SourceText",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=6.8,
            leading=9,
            textColor=CYAN,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Empty",
            parent=styles["BodySmall"],
            textColor=MUTED,
        )
    )

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=19 * mm,
        bottomMargin=17 * mm,
        title=f"ThreatLens CVE Report - {detail.cve_id}",
        author="ThreatLens",
        subject=f"Threat intelligence detail for {detail.cve_id}",
    )
    story = []

    severity_color = _severity_color(detail.severity)
    heading = Table(
        [
            [
                Paragraph(f"<b>{_text(detail.cve_id)}</b>", styles["ReportTitle"]),
                Paragraph(
                    f'<para alignment="center"><b>{_text(detail.severity.upper())}</b><br/>'
                    f'<font size="14">{detail.cvss_score:.1f}</font></para>',
                    ParagraphStyle(
                        "SeverityBox",
                        parent=styles["TableText"],
                        alignment=TA_CENTER,
                        textColor=colors.white,
                        leading=16,
                    ),
                ),
            ]
        ],
        colWidths=[145 * mm, 32 * mm],
    )
    heading.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND", (1, 0), (1, 0), severity_color),
                ("BOX", (1, 0), (1, 0), 0.5, severity_color),
                ("LEFTPADDING", (1, 0), (1, 0), 3 * mm),
                ("RIGHTPADDING", (1, 0), (1, 0), 3 * mm),
                ("TOPPADDING", (1, 0), (1, 0), 3 * mm),
                ("BOTTOMPADDING", (1, 0), (1, 0), 3 * mm),
            ]
        )
    )
    story.append(heading)
    story.append(Paragraph(_text(detail.title), styles["ReportSubtitle"]))
    story.append(Spacer(1, 4 * mm))

    meta_data = [
        [
            Paragraph("<b>Vendor / Product</b>", styles["TableTextMuted"]),
            Paragraph(f"{_text(detail.vendor)} / {_text(detail.product or 'Unknown')}", styles["TableText"]),
            Paragraph("<b>Published</b>", styles["TableTextMuted"]),
            Paragraph(detail.published_at.strftime("%d %b %Y"), styles["TableText"]),
        ],
        [
            Paragraph("<b>KEV</b>", styles["TableTextMuted"]),
            Paragraph("Yes" if detail.kev else "No", styles["TableText"]),
            Paragraph("<b>Data sources</b>", styles["TableTextMuted"]),
            Paragraph(_text(detail.detail_source), styles["TableText"]),
        ],
    ]
    meta = Table(meta_data, colWidths=[29 * mm, 61 * mm, 25 * mm, 62 * mm])
    meta.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE),
                ("GRID", (0, 0), (-1, -1), 0.35, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2.2 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2.2 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 1.8 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8 * mm),
            ]
        )
    )
    story.append(meta)

    story.append(Paragraph("Executive Summary", styles["Section"]))
    story.append(Paragraph(_text(detail.description), styles["BodySmall"]))
    if detail.weaknesses:
        story.append(
            Paragraph(
                f"<b>Weakness:</b> {_text(', '.join(detail.weaknesses))}",
                styles["BodySmall"],
            )
        )

    story.append(Paragraph("Root Cause", styles["Section"]))
    root_cause = detail.root_cause
    root_rows = [
        ["Category", "Confidence", "Evidence basis"],
        [root_cause.category, root_cause.confidence, root_cause.basis or "-"],
    ]
    root_table = Table(
        [
            [
                Paragraph(_text(cell), styles["TableHeader"] if row_index == 0 else styles["TableText"])
                for cell in row
            ]
            for row_index, row in enumerate(root_rows)
        ],
        colWidths=[55 * mm, 35 * mm, 88 * mm],
        repeatRows=1,
    )
    root_table.setStyle(_table_style())
    story.append(root_table)
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(_text(root_cause.summary), styles["BodySmall"]))

    story.append(Paragraph("Potential MITRE ATT&CK", styles["Section"]))
    if detail.mitre_techniques:
        rows = [["Technique", "Tactic", "Rationale", "Confidence"]]
        rows.extend(
            [
                f"{item.technique_id} - {item.name}",
                item.tactic,
                item.rationale,
                item.confidence,
            ]
            for item in detail.mitre_techniques
        )
        table = Table(
            [
                [
                    Paragraph(_text(cell), styles["TableHeader"] if index == 0 else styles["TableText"])
                    for cell in row
                ]
                for index, row in enumerate(rows)
            ],
            colWidths=[46 * mm, 34 * mm, 73 * mm, 25 * mm],
            repeatRows=1,
        )
        table.setStyle(_table_style())
        story.append(table)
        story.append(
            Paragraph(
                "Mapping is heuristic and based on CVSS, CWE, and exploit conditions; it is not threat-actor attribution.",
                styles["TableTextMuted"],
            )
        )
    else:
        story.append(
            Paragraph(
                "No defensible ATT&CK relationship could be derived from the current evidence.",
                styles["Empty"],
            )
        )

    story.append(Paragraph("CVSS Matrix", styles["Section"]))
    if detail.cvss:
        cvss = detail.cvss
        story.append(
            Paragraph(
                f"<b>CVSS { _text(cvss.version) } vector:</b> {_text(cvss.vector or 'Not available')}",
                styles["BodySmall"],
            )
        )
        cvss_rows = [
            ["Metric", "Value", "Metric", "Value"],
            ["Attack Vector", cvss.attack_vector, "Attack Complexity", cvss.attack_complexity],
            ["Privileges Required", cvss.privileges_required, "User Interaction", cvss.user_interaction],
            ["Scope", cvss.scope, "Confidentiality", cvss.confidentiality_impact],
            ["Integrity", cvss.integrity_impact, "Availability", cvss.availability_impact],
            ["Exploitability", cvss.exploitability_score or "-", "Impact", cvss.impact_score or "-"],
        ]
        cvss_table = Table(
            [[Paragraph(_text(cell), styles["TableHeader"]) if row_index == 0 else Paragraph(_text(cell), styles["TableText"]) for cell in row] for row_index, row in enumerate(cvss_rows)],
            colWidths=[39 * mm, 49.5 * mm, 39 * mm, 49.5 * mm],
            repeatRows=1,
        )
        cvss_table.setStyle(_table_style())
        story.append(cvss_table)
    else:
        story.append(Paragraph("CVSS matrix is not available from the current sources.", styles["Empty"]))

    story.append(Paragraph("Exploitation Status", styles["Section"]))
    exploit = detail.exploit_status
    exploit_rows = [
        ["Known exploited", "KEV date", "Ransomware use", "Action due"],
        [
            "Yes" if exploit.known_exploited else "Not recorded",
            exploit.date_added or "-",
            exploit.ransomware_use,
            exploit.action_due or "-",
        ],
    ]
    exploit_table = Table(
        [[Paragraph(_text(cell), styles["TableHeader"]) if row_index == 0 else Paragraph(_text(cell), styles["TableText"]) for cell in row] for row_index, row in enumerate(exploit_rows)],
        colWidths=[44.5 * mm] * 4,
        repeatRows=1,
    )
    exploit_table.setStyle(_table_style())
    story.append(exploit_table)

    story.append(Paragraph("Affected Products", styles["Section"]))
    if detail.affected_products:
        rows = [["Vendor", "Product", "Version", "Affected range"]]
        rows.extend(
            [
                item.vendor,
                item.product,
                item.version,
                item.version_range or "-",
            ]
            for item in detail.affected_products
        )
        table = Table(
            [[Paragraph(_text(cell), styles["TableHeader"]) if index == 0 else Paragraph(_text(cell), styles["TableText"]) for cell in row] for index, row in enumerate(rows)],
            colWidths=[38 * mm, 49 * mm, 39 * mm, 52 * mm],
            repeatRows=1,
        )
        table.setStyle(_table_style())
        story.append(table)
    else:
        story.append(Paragraph("No affected product data is available.", styles["Empty"]))

    _append_remediation(story, "Mitigation", detail.mitigation, styles)
    _append_remediation(story, "Workarounds", detail.workarounds, styles)

    story.append(Paragraph("Related Assets", styles["Section"]))
    if detail.related_assets:
        rows = [["Asset", "Type", "OS / Version", "Owner", "Risk"]]
        rows.extend(
            [item.name, item.asset_type, item.os_version or "-", item.owner or "-", item.risk]
            for item in detail.related_assets
        )
        table = Table(
            [[Paragraph(_text(cell), styles["TableHeader"]) if index == 0 else Paragraph(_text(cell), styles["TableText"]) for cell in row] for index, row in enumerate(rows)],
            colWidths=[38 * mm, 34 * mm, 44 * mm, 35 * mm, 27 * mm],
            repeatRows=1,
        )
        table.setStyle(_table_style())
        story.append(table)
    else:
        story.append(Paragraph("No monitored assets are linked to this CVE.", styles["Empty"]))

    story.append(Paragraph("Related IOC", styles["Section"]))
    if detail.related_iocs:
        rows = [["Indicator", "Type", "Threat", "Severity", "Source"]]
        rows.extend(
            [item.indicator, item.type, item.threat, item.severity, item.source]
            for item in detail.related_iocs
        )
        table = Table(
            [[Paragraph(_text(cell), styles["TableHeader"]) if index == 0 else Paragraph(_text(cell), styles["TableText"]) for cell in row] for index, row in enumerate(rows)],
            colWidths=[52 * mm, 22 * mm, 39 * mm, 27 * mm, 38 * mm],
            repeatRows=1,
        )
        table.setStyle(_table_style())
        story.append(table)
    else:
        story.append(Paragraph("No verified IOC relationship is currently available.", styles["Empty"]))

    story.append(Paragraph("Remediation Resources", styles["Section"]))
    if detail.remediation_sources:
        for index, item in enumerate(detail.remediation_sources[:30], start=1):
            label = item.tags[0] if item.tags else item.source or _source_label(item.url, "Source")
            story.append(
                Paragraph(
                    f"<b>{index}. {_text(label)}</b><br/>{_link(item.url, item.url)}",
                    styles["BodySmall"],
                )
            )
    else:
        story.append(Paragraph("No remediation resources are available.", styles["Empty"]))

    story.append(Paragraph("References", styles["Section"]))
    if detail.references:
        for index, item in enumerate(detail.references[:40], start=1):
            label = item.tags[0] if item.tags else item.source or _source_label(item.url, "Reference")
            story.append(
                Paragraph(
                    f"<b>{index}. {_text(label)}</b><br/>{_link(item.url, item.url)}",
                    styles["BodySmall"],
                )
            )
    else:
        story.append(Paragraph("No reference links are available.", styles["Empty"]))

    def page_chrome(canvas, doc) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(16 * mm, height - 12 * mm, width - 16 * mm, height - 12 * mm)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(NAVY)
        canvas.drawString(16 * mm, height - 9 * mm, "ThreatLens - CVE Intelligence Report")
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(width - 16 * mm, height - 9 * mm, detail.cve_id)
        canvas.line(16 * mm, 11 * mm, width - 16 * mm, 11 * mm)
        canvas.drawString(16 * mm, 7.5 * mm, "Generated from cached NVD, CISA KEV, CVE.org, GitHub, and vendor advisory data.")
        canvas.drawRightString(width - 16 * mm, 7.5 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
    return buffer.getvalue()


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 1.8 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 1.8 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 1.6 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6 * mm),
        ]
    )


def _append_remediation(story: list, title: str, items: list, styles: dict) -> None:
    story.append(Paragraph(title, styles["Section"]))
    if not items:
        story.append(Paragraph(f"No verified {title.lower()} are available from the current sources.", styles["Empty"]))
        return
    for index, item in enumerate(items, start=1):
        source = _link(item.url, item.source) if item.url else _text(item.source)
        story.append(
            Paragraph(
                f"<b>{index}.</b> {_text(item.text)}<br/><font size=\"6.8\" color=\"#087E9B\">Source: {source}</font>",
                styles["BodySmall"],
            )
        )
