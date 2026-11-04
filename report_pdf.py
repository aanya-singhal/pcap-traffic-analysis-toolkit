"""
PDF export of the CIA Security Posture report for an analysis.
Rendered with ReportLab (already a project dependency). Pure function:
takes the already-computed analysis data and returns PDF bytes.
"""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

NAVY = colors.HexColor("#2D3A66")
AMBER = colors.HexColor("#C2410C")
LIGHT = colors.HexColor("#EDF0F8")
GREY = colors.HexColor("#444444")

_BADGE = {
    "PASS": colors.HexColor("#15803d"),
    "WARNING": colors.HexColor("#b45309"),
    "FAIL": colors.HexColor("#be123c"),
}
_SEV = {
    "High": colors.HexColor("#be123c"),
    "Medium": colors.HexColor("#b45309"),
    "Low": colors.HexColor("#0369a1"),
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("CIATitle", parent=ss["Title"], textColor=NAVY, fontSize=20, spaceAfter=2))
    ss.add(ParagraphStyle("CIASub", parent=ss["Normal"], textColor=GREY, fontSize=9, spaceAfter=10))
    ss.add(ParagraphStyle("H1", parent=ss["Heading2"], textColor=NAVY, fontSize=13, spaceBefore=12, spaceAfter=6))
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8, leading=10))
    ss.add(ParagraphStyle("CellSmall", parent=ss["Normal"], fontSize=7, leading=9, textColor=GREY))
    return ss


def generate_report_pdf(analysis, findings, posture_score, pillar_cards,
                        posture_band, severity_counts):
    """
    analysis:       dict-like with id, filename, file_size, parse_seconds, detect_seconds
    findings:       list of dicts (pillar, severity, rule, src_ip, dst_ip, detail, evidence)
    posture_score:  int 0-100
    pillar_cards:   {pillar: {status, score, violations_count, summary}}
    posture_band:   {rating, description}
    severity_counts:{High, Medium, Low}
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            title="CIA Security Posture Report")
    ss = _styles()
    story = []

    # --- Header ---
    story.append(Paragraph("CIA Security Posture Report", ss["CIATitle"]))
    story.append(Paragraph(
        "Automated PCAP &amp; Network Traffic Analysis Toolkit &nbsp;·&nbsp; "
        "Information Security Lab (ICT 3141)", ss["CIASub"]))

    fname = analysis["filename"] if analysis["filename"] else "capture"
    size_mb = (analysis["file_size"] or 0) / (1024 * 1024)
    meta = [
        ["Capture", str(fname)],
        ["Analysis ID", f"#{analysis['id']}"],
        ["Size", f"{size_mb:.2f} MB"],
        ["Parsed in", f"{(analysis['parse_seconds'] or 0):.2f} s   ·   rules in {(analysis['detect_seconds'] or 0):.3f} s"],
        ["Generated", datetime.now().strftime("%d %b %Y, %H:%M")],
    ]
    t = Table(meta, colWidths=[32 * mm, 140 * mm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, LIGHT),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))

    # --- Posture score banner ---
    band = posture_band.get("rating", "")
    desc = posture_band.get("description", "")
    score_tbl = Table(
        [[Paragraph(f"<b>{posture_score}</b>", ParagraphStyle("Big", fontSize=34, textColor=NAVY, alignment=1)),
          Paragraph(f"<b>CIA Security Health Score</b> &nbsp; <font size=9 color='#C2410C'>{band}</font><br/>"
                    f"<font size=8 color='#444444'>{desc}</font>",
                    ParagraphStyle("BandP", fontSize=11, leading=15))]],
        colWidths=[30 * mm, 142 * mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 10))

    # --- Four pillar cards ---
    story.append(Paragraph("Four Pillars Status", ss["H1"]))
    header = ["Pillar", "Status", "Health", "Violations"]
    rows = [header]
    for pillar in ["Confidentiality", "Integrity", "Authentication", "Availability"]:
        c = pillar_cards.get(pillar, {})
        rows.append([pillar, c.get("status", "—"),
                     f"{c.get('score', 0)} / 25", str(c.get("violations_count", 0))])
    pt = Table(rows, colWidths=[55 * mm, 40 * mm, 40 * mm, 37 * mm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(rows)):
        st = rows[i][1]
        if st in _BADGE:
            style.append(("TEXTCOLOR", (1, i), (1, i), _BADGE[st]))
            style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
    pt.setStyle(TableStyle(style))
    story.append(pt)
    story.append(Spacer(1, 10))

    # --- Findings ---
    sc = severity_counts
    story.append(Paragraph(
        f"Security Findings ({len(findings)}) &nbsp; "
        f"<font size=8 color='#444444'>High: {sc.get('High',0)}  ·  "
        f"Medium: {sc.get('Medium',0)}  ·  Low: {sc.get('Low',0)}</font>", ss["H1"]))

    if findings:
        head = ["Pillar", "Severity", "Rule", "Source", "Target", "Why flagged"]
        frows = [head]
        for f in findings:
            frows.append([
                Paragraph(str(f.get("pillar", "—")), ss["CellSmall"]),
                Paragraph(str(f.get("severity", "—")), ss["CellSmall"]),
                Paragraph(str(f.get("rule", "—")), ss["Cell"]),
                Paragraph(str(f.get("src_ip") or "—"), ss["CellSmall"]),
                Paragraph(str(f.get("dst_ip") or "—"), ss["CellSmall"]),
                Paragraph(str(f.get("detail", ""))[:300], ss["CellSmall"]),
            ])
        ft = Table(frows, colWidths=[24 * mm, 17 * mm, 28 * mm, 24 * mm, 24 * mm, 55 * mm], repeatRows=1)
        fstyle = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, LIGHT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i in range(1, len(frows)):
            sev = str(findings[i - 1].get("severity", ""))
            if sev in _SEV:
                fstyle.append(("TEXTCOLOR", (1, i), (1, i), _SEV[sev]))
                fstyle.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        ft.setStyle(TableStyle(fstyle))
        story.append(ft)
    else:
        story.append(Paragraph("No threats detected — telemetry conforms to the security baseline.", ss["Cell"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "<font size=7 color='#888888'>Findings are rule-based indicators for investigation, "
        "mapped to the CIA Triad. Every finding is verifiable packet-by-packet on the source capture.</font>",
        ss["Cell"]))

    doc.build(story)
    buf.seek(0)
    return buf.read()
