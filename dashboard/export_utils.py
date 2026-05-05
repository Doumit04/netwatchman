"""
export_utils.py  –  NetWatchman PDF + CSV export
Drop this file into dashboard/ alongside app.py.

Dependencies:
    pip install reportlab
"""

import csv
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ── Palette ───────────────────────────────────────────────────────────────────
_BG       = colors.HexColor("#0d1117")
_SURFACE  = colors.HexColor("#161b22")
_BORDER   = colors.HexColor("#21262d")
_TEXT     = colors.HexColor("#e6edf3")
_MUTED    = colors.HexColor("#8b949e")
_CRITICAL = colors.HexColor("#ff4444")
_HIGH     = colors.HexColor("#ff8800")
_MEDIUM   = colors.HexColor("#ffcc00")
_LOW      = colors.HexColor("#33cc66")
_INFO     = colors.HexColor("#4da6ff")
_ACCENT   = colors.HexColor("#58a6ff")

_SEV_COLOR = {
    "critical": _CRITICAL, "high": _HIGH,
    "medium":   _MEDIUM,   "low":  _LOW,
    "info":     _INFO,
}

# Fields checked in order when looking for a human-readable description.
# Add any detector-specific field names here if needed.
_DESC_FIELDS = [
    "description", "detail", "message", "msg", "alert",
    "info", "reason", "credential", "data", "note", "summary",
]


def _get_desc(r: dict) -> str:
    """Return the best description string from an alert dict."""
    for field in _DESC_FIELDS:
        v = r.get(field)
        if v and str(v).strip() and str(v).strip() != "—":
            return str(v).strip()
    # Last resort: concatenate any unknown non-empty scalar fields
    skip = {"severity", "detector", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "timestamp", "type", "source", "destination",
            "mitre_id", "mitre", "mitre_name"}
    extras = [f"{k}: {v}" for k, v in r.items()
              if k not in skip and v not in (None, "", "—")]
    return " · ".join(extras) if extras else "—"


# ─────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────

def build_pdf(scan_meta: dict, results: list) -> bytes:
    """Return a styled PDF as raw bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=18*mm,  bottomMargin=18*mm,
    )
    styles = _make_styles()
    story  = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("NetWatchman", styles["brand"]))
    story.append(Paragraph("Network Intrusion Detection Report", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BORDER, spaceAfter=6))

    # ── Scan meta ─────────────────────────────────────────────────────────────
    meta_data = [
        ["Source",    scan_meta.get("source_name", "—"),
         "Mode",      scan_meta.get("mode", "—").upper()],
        ["Scan time", scan_meta.get("created_at",  "—"),
         "Packets",   str(scan_meta.get("total_packets", 0))],
        ["Total alerts", str(scan_meta.get("total", len(results))),
         "", ""],
    ]
    meta_tbl = Table(meta_data, colWidths=[28*mm, 72*mm, 24*mm, 46*mm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0),(-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("TEXTCOLOR",     (0,0),(-1,-1), _TEXT),
        ("TEXTCOLOR",     (0,0),(0,-1),  _MUTED),
        ("TEXTCOLOR",     (2,0),(2,-1),  _MUTED),
        ("BACKGROUND",    (0,0),(-1,-1), _SURFACE),
        ("BOX",           (0,0),(-1,-1), 0.5, _BORDER),
        ("INNERGRID",     (0,0),(-1,-1), 0.5, _BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 7),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    # ── Severity cards ────────────────────────────────────────────────────────
    story.append(Paragraph("Severity Breakdown", styles["section_heading"]))
    sev_keys = ["critical", "high", "medium", "low", "info"]
    sev_vals = [str(scan_meta.get(k, 0)) for k in sev_keys]
    sev_tbl  = Table([sev_keys, sev_vals], colWidths=[36*mm]*5)
    sev_tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0),(-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,0),  7),
        ("FONTSIZE",      (0,1),(-1,1),  14),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("TEXTCOLOR",     (0,0),(-1,-1), _BG),
        *[("BACKGROUND", (i,0),(i,-1), _SEV_COLOR[sev_keys[i]]) for i in range(5)],
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
        ("INNERGRID",     (0,0),(-1,-1), 0.5, _BG),
    ]))
    story.append(sev_tbl)
    story.append(Spacer(1, 12))

    # ── Alerts table ──────────────────────────────────────────────────────────
    story.append(Paragraph(f"Alert Details  ({len(results)} events)", styles["section_heading"]))

    if not results:
        story.append(Paragraph("No alerts detected.", styles["body"]))
    else:
        # Column widths: #, Sev, Detector, Src, Dst, Description (fills rest)
        col_widths = [10*mm, 18*mm, 28*mm, 28*mm, 28*mm, None]
        headers = ["#", "Severity", "Detector", "Src IP", "Dst IP", "Description"]

        body_style = ParagraphStyle(
            "cell", fontName="Helvetica", fontSize=7,
            textColor=_TEXT, leading=9, wordWrap="LTR",
        )
        sev_style = ParagraphStyle(
            "sev", fontName="Helvetica-Bold", fontSize=7,
            leading=9, wordWrap="LTR",
        )

        rows = [headers]
        for i, r in enumerate(results, 1):
            sev  = (r.get("severity") or "info").lower()
            col  = _SEV_COLOR.get(sev, _INFO)
            desc = _get_desc(r)

            rows.append([
                Paragraph(str(i),  body_style),
                Paragraph(sev.upper(), ParagraphStyle(
                    "s", fontName="Helvetica-Bold", fontSize=7,
                    textColor=col, leading=9)),
                Paragraph(str(r.get("detector", r.get("type", "—")))[:28], body_style),
                Paragraph(str(r.get("src_ip",  r.get("source",      "—")))[:20], body_style),
                Paragraph(str(r.get("dst_ip",  r.get("destination", "—")))[:20], body_style),
                Paragraph(desc, body_style),
            ])

        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        row_styles = [
            ("BACKGROUND",    (0,0),(-1,0),  _ACCENT),
            ("TEXTCOLOR",     (0,0),(-1,0),  _BG),
            ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,0),  7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [_SURFACE, _BG]),
            ("BOX",           (0,0),(-1,-1), 0.5, _BORDER),
            ("INNERGRID",     (0,0),(-1,-1), 0.25, _BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 4),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ("ALIGN",         (0,0),(0,-1),  "CENTER"),
        ]
        tbl.setStyle(TableStyle(row_styles))
        story.append(tbl)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER))
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(
        f"Generated by NetWatchman  ·  {ts}", styles["footer"],
    ))

    doc.build(story)
    return buf.getvalue()


def build_csv(scan_meta: dict, results: list) -> str:
    """Return UTF-8 CSV string of all alerts."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")

    writer.writerow(["# NetWatchman Scan Report"])
    writer.writerow(["# Source",        scan_meta.get("source_name", "")])
    writer.writerow(["# Mode",          scan_meta.get("mode", "")])
    writer.writerow(["# Scan time",     scan_meta.get("created_at", "")])
    writer.writerow(["# Total packets", scan_meta.get("total_packets", 0)])
    writer.writerow(["# Total alerts",  scan_meta.get("total", len(results))])
    writer.writerow([])

    if not results:
        writer.writerow(["No alerts."])
        return buf.getvalue()

    base_cols = ["severity", "detector", "type", "src_ip", "source",
                 "dst_ip", "destination", "description", "detail",
                 "message", "msg", "alert", "info", "timestamp",
                 "protocol", "port", "src_port", "dst_port"]
    all_keys  = list(dict.fromkeys(
        base_cols + [k for r in results for k in r if k not in base_cols]
    ))
    present = [k for k in all_keys if any(k in r for r in results)]

    writer.writerow(["#"] + present)
    for i, r in enumerate(results, 1):
        writer.writerow([i] + [r.get(k, "") for k in present])

    return buf.getvalue()


# ─────────────────────────────────────────────
#  Private helpers
# ─────────────────────────────────────────────

def _make_styles():
    def P(name, **kw):
        return ParagraphStyle(name, **kw)
    return {
        "brand":    P("brand",    fontName="Helvetica-Bold", fontSize=22,
                      textColor=_ACCENT, spaceAfter=2),
        "subtitle": P("subtitle", fontName="Helvetica", fontSize=10,
                      textColor=_MUTED, spaceAfter=8),
        "section_heading": P("sh", fontName="Helvetica-Bold", fontSize=10,
                              textColor=_ACCENT, spaceBefore=8, spaceAfter=4),
        "body":     P("body",     fontName="Helvetica", fontSize=9, textColor=_TEXT),
        "footer":   P("footer",   fontName="Helvetica", fontSize=7,
                      textColor=_MUTED, alignment=TA_CENTER, spaceBefore=4),
    }