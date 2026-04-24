"""PDF builder for the deep forensic report.

Produces a single REPORT.pdf included at the root of the exported
ZIP. The layout is deliberately plain: the goal is readability on
screen AND print, by a non-technical recipient (user, family, law
enforcement).

Uses reportlab's Platypus high-level API for flow layout so long
paragraphs wrap naturally. All content is UTF-8; markdown headings
from Opus are mapped to reportlab styles manually (no full markdown
parser — we trust the system prompt to use only a handful of levels).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _markdown_to_flowables(markdown_text: str, styles: Any) -> list[Any]:
    """Very small markdown → Paragraph list converter.

    Supports:
        - `# ` / `## ` / `### ` headings.
        - Bullet lists (lines starting with `- `).
        - Blank-line paragraph separation.

    Anything more ornate (tables, code blocks) falls back to preformatted
    paragraphs, which is still readable.
    """
    flow: list[Any] = []
    paragraph_buffer: list[str] = []

    def _flush_paragraph() -> None:
        if not paragraph_buffer:
            return
        text = " ".join(paragraph_buffer).strip()
        if text:
            flow.append(Paragraph(_escape(text), styles["body"]))
            flow.append(Spacer(1, 0.2 * cm))
        paragraph_buffer.clear()

    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if not line:
            _flush_paragraph()
            continue
        if line.startswith("### "):
            _flush_paragraph()
            flow.append(Paragraph(_escape(line[4:]), styles["h3"]))
            continue
        if line.startswith("## "):
            _flush_paragraph()
            flow.append(Paragraph(_escape(line[3:]), styles["h2"]))
            continue
        if line.startswith("# "):
            _flush_paragraph()
            flow.append(Paragraph(_escape(line[2:]), styles["h1"]))
            continue
        if line.startswith("- ") or line.startswith("* "):
            _flush_paragraph()
            flow.append(Paragraph(f"• {_escape(line[2:])}", styles["bullet"]))
            continue
        paragraph_buffer.append(line)

    _flush_paragraph()
    return flow


def _escape(text: str) -> str:
    """Minimal HTML escape for reportlab's Paragraph parser."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_styles() -> dict[str, ParagraphStyle]:
    """Custom reportlab styles tuned for a readable incident report."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontSize=20,
            leading=24,
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontSize=11,
            textColor="#555555",
            leading=14,
            spaceAfter=16,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], spaceBefore=12, spaceAfter=6, fontSize=16
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], spaceBefore=10, spaceAfter=4, fontSize=14
        ),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"], spaceBefore=8, spaceAfter=4, fontSize=12
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontSize=10.5,
            leading=14,
            alignment=TA_LEFT,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base["BodyText"],
            fontSize=10.5,
            leading=14,
            leftIndent=20,
            bulletIndent=6,
        ),
        "meta": ParagraphStyle(
            "meta",
            parent=base["Normal"],
            fontSize=9,
            textColor="#333333",
        ),
    }


def build_report_pdf(
    output_path: Path,
    *,
    title: str,
    generated_at_utc: Optional[datetime] = None,
    alert_summary: Optional[dict[str, Any]] = None,
    executive_md: str = "",
    technical_md: str = "",
    ioc_rows: Optional[list[dict[str, Any]]] = None,
    attack_rows: Optional[list[dict[str, Any]]] = None,
    timeline_rows: Optional[list[dict[str, Any]]] = None,
) -> Path:
    """Render a full deep-forensic PDF to ``output_path``.

    Args:
        output_path: Target file (overwritten if present).
        title: Cover-page title (typically the incident IP).
        generated_at_utc: When the PDF is produced (defaults to now).
        alert_summary: Small key/value dict rendered as the cover table.
        executive_md / technical_md: Markdown bodies, usually from Opus.
        ioc_rows / attack_rows / timeline_rows: Tabular data.

    Returns:
        Absolute path of the written PDF (same as ``output_path``).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = _build_styles()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=title,
        author="WardSOAR",
    )
    flow: list[Any] = []

    # --- Cover page --------------------------------------------------
    ts = (generated_at_utc or datetime.now(timezone.utc)).astimezone(timezone.utc)
    flow.append(Paragraph(_escape(title), styles["title"]))
    flow.append(
        Paragraph(
            f"WardSOAR Incident Report — generated {ts.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles["subtitle"],
        )
    )

    if alert_summary:
        flow.append(_kv_table(alert_summary))
        flow.append(Spacer(1, 0.4 * cm))

    # --- Executive summary -------------------------------------------
    if executive_md.strip():
        flow.append(Paragraph("Executive summary", styles["h1"]))
        flow.extend(_markdown_to_flowables(executive_md, styles))
        flow.append(Spacer(1, 0.3 * cm))

    # --- Technical analysis ------------------------------------------
    if technical_md.strip():
        flow.append(PageBreak())
        flow.append(Paragraph("Technical analysis", styles["h1"]))
        flow.extend(_markdown_to_flowables(technical_md, styles))

    # --- MITRE ATT&CK table ------------------------------------------
    if attack_rows:
        flow.append(Spacer(1, 0.6 * cm))
        flow.append(Paragraph("MITRE ATT&CK mapping", styles["h2"]))
        flow.append(_attack_table(attack_rows))

    # --- IOC table ---------------------------------------------------
    if ioc_rows:
        flow.append(Spacer(1, 0.6 * cm))
        flow.append(Paragraph("Indicators of compromise", styles["h2"]))
        flow.append(_ioc_table(ioc_rows))

    # --- Timeline excerpt --------------------------------------------
    if timeline_rows:
        flow.append(Spacer(1, 0.6 * cm))
        flow.append(Paragraph("Timeline (condensed)", styles["h2"]))
        flow.append(_timeline_table(timeline_rows))

    flow.append(Spacer(1, 1 * cm))
    flow.append(
        Paragraph(
            "This report was generated automatically. Evidence files and their "
            "SHA-256 checksums are included in the exported ZIP. "
            "For the technical reader: MANIFEST.json lists every artefact.",
            styles["meta"],
        )
    )

    doc.build(flow)
    return output_path


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------


def _kv_table(data: dict[str, Any]) -> Table:
    """Two-column key/value table used on the cover page."""
    rows = [[_escape(str(k)), _escape(str(v))] for k, v in data.items()]
    table = Table(rows, colWidths=[5 * cm, 11 * cm])
    table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), "#555555"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _attack_table(rows: list[dict[str, Any]]) -> Table:
    """Tactic | Technique | Confidence | Triggers."""
    header = ["Tactic", "Technique", "Confidence", "Triggers"]
    body = []
    for r in rows:
        body.append(
            [
                _escape(str(r.get("tactic", ""))),
                _escape(f"{r.get('technique_id', '')} — {r.get('name', '')}"),
                f"{float(r.get('confidence', 0)) * 100:.0f}%",
                _escape(", ".join(r.get("triggers", []))[:80]),
            ]
        )
    return _styled_table([header, *body], col_widths=[3 * cm, 7 * cm, 2.5 * cm, 4 * cm])


def _ioc_table(rows: list[dict[str, Any]]) -> Table:
    """Type | Value | Source."""
    header = ["Type", "Value", "Source"]
    body = []
    for r in rows[:60]:  # cap for legibility; full set lives in JSON
        if r["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
            value = str(r.get("value", ""))
        elif r["type"] == "file":
            hashes = r.get("hashes") or {}
            value = (
                hashes.get("SHA-256") or hashes.get("MD5") or r.get("path", "") or r.get("name", "")
            )
        else:
            value = ""
        body.append(
            [
                _escape(str(r["type"])),
                _escape(str(value)[:80]),
                _escape(str(r.get("_source", ""))),
            ]
        )
    return _styled_table([header, *body], col_widths=[3 * cm, 9 * cm, 4.5 * cm])


def _timeline_table(rows: list[dict[str, Any]]) -> Table:
    """Timestamp | Source | Description."""
    header = ["Timestamp (UTC)", "Source", "Description"]
    body = []
    for r in rows[:40]:
        body.append(
            [
                _escape(str(r.get("timestamp_utc", ""))),
                _escape(str(r.get("source", ""))),
                _escape(str(r.get("description", ""))[:110]),
            ]
        )
    return _styled_table([header, *body], col_widths=[4.5 * cm, 2.5 * cm, 9.5 * cm])


def _styled_table(rows: list[list[str]], col_widths: list[float]) -> Table:
    """Shared table cosmetics for the IOC / ATT&CK / Timeline tables."""
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), "#2F4858"),
                ("TEXTCOLOR", (0, 0), (-1, 0), "#FFFFFF"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("GRID", (0, 0), (-1, -1), 0.25, "#CCCCCC"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), ["#FFFFFF", "#F5F5F5"]),
            ]
        )
    )
    return table
