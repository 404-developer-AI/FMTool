"""Migration report builder: gathers data, produces CSV and PDF exports."""

import csv
import io
import os
from datetime import datetime

from app.models.database import (
    get_activity_items_in_range,
    get_last_activity_per_item,
    get_last_import,
    get_sophos_objects_for_items,
    get_table_items,
)
from app.services.branding import get_logo_path, get_report_settings

FMTOOL_VERSION = "0.8c"

# Categories that have migration state and are included in report scopes.
# Each entry maps scope name -> (db_table, label, name_field, type_field_or_static)
REPORT_CATEGORIES = {
    "aliases": {
        "table": "aliases",
        "label": "Aliases",
        "name_field": "name",
        "type_field": "type",
    },
    "firewall_rules": {
        "table": "firewall_rules",
        "label": "Firewall Rules",
        "name_field": "descr",
        "type_field": None,  # use interface as type hint
        "type_hint_field": "interface",
    },
    "nat_rules": {
        "table": "nat_rules",
        "label": "NAT Rules",
        "name_field": "descr",
        "type_field": None,
        "type_hint_field": "interface",
    },
}

GLOBAL_SCOPE_CATEGORIES = ["aliases", "firewall_rules", "nat_rules"]

STATUS_ORDER = ["migrated", "failed", "skipped", "pending"]


def _format_sophos_objects(objects):
    """Format a list of sophos_object dicts into display strings."""
    return [f"{o['sophos_name']} ({o['sophos_type']})" for o in objects]


def _item_display_name(row, cfg):
    """Return best display name for an item row."""
    name = row.get(cfg["name_field"]) or ""
    if not name:
        name = f"#{row.get('id', '?')}"
    return name


def _item_type(row, cfg):
    """Return type/subtype for an item row."""
    if cfg.get("type_field"):
        return row.get(cfg["type_field"]) or ""
    hint_field = cfg.get("type_hint_field")
    if hint_field:
        return row.get(hint_field) or ""
    return ""


def _collect_category_items(db_path, category, restrict_ids=None):
    """Fetch items for a single report category, enriched with Sophos objects + activity."""
    cfg = REPORT_CATEGORIES[category]
    table = cfg["table"]

    all_rows = get_table_items(db_path, table)
    if restrict_ids is not None:
        restrict = set(restrict_ids)
        all_rows = [r for r in all_rows if r["id"] in restrict]

    if not all_rows:
        return []

    ids = [r["id"] for r in all_rows]
    sophos_map = get_sophos_objects_for_items(db_path, table, ids)
    # Activity log uses category names matching DETAIL_TABLES keys
    activity_map = get_last_activity_per_item(db_path, category, ids)

    items = []
    for row in all_rows:
        iid = row["id"]
        sophos_objs = sophos_map.get(iid, [])
        activity = activity_map.get(iid, {})
        items.append({
            "category": category,
            "category_label": cfg["label"],
            "item_id": iid,
            "item_name": _item_display_name(row, cfg),
            "item_type": _item_type(row, cfg),
            "status": row.get("migration_status") or "pending",
            "sophos_objects": _format_sophos_objects(sophos_objs),
            "last_action_at": activity.get("timestamp") or "",
            "error_message": activity.get("error_message") or "",
        })
    return items


def _empty_summary():
    return {"total": 0, "migrated": 0, "pending": 0, "skipped": 0, "failed": 0}


def _add_to_summary(summary, status):
    summary["total"] += 1
    if status in summary:
        summary[status] += 1
    else:
        summary["pending"] += 1


def build_report_data(db_path, branding_folder, scope="global",
                      mode="snapshot", date_from=None, date_to=None):
    """Build the report data structure used by CSV and PDF generators.

    scope: "global" | "aliases" | "firewall_rules" | "nat_rules"
    mode:  "snapshot" (current status) | "range" (items with activity in date range)
    """
    if scope == "global":
        categories = GLOBAL_SCOPE_CATEGORIES[:]
    elif scope in REPORT_CATEGORIES:
        categories = [scope]
    else:
        categories = GLOBAL_SCOPE_CATEGORIES[:]
        scope = "global"

    restrict_by_category = None
    if mode == "range" and date_from and date_to:
        restrict_by_category = {c: set() for c in categories}
        pairs = get_activity_items_in_range(db_path, date_from, date_to)
        for cat, iid in pairs:
            if cat in restrict_by_category and iid is not None:
                restrict_by_category[cat].add(iid)

    items = []
    per_category_summary = {}
    global_summary = _empty_summary()

    for category in categories:
        restrict_ids = None
        if restrict_by_category is not None:
            restrict_ids = restrict_by_category.get(category, set())
            if not restrict_ids:
                per_category_summary[category] = {
                    "label": REPORT_CATEGORIES[category]["label"],
                    **_empty_summary(),
                }
                continue

        cat_items = _collect_category_items(db_path, category, restrict_ids)
        cat_summary = _empty_summary()
        for it in cat_items:
            _add_to_summary(cat_summary, it["status"])
            _add_to_summary(global_summary, it["status"])
        per_category_summary[category] = {
            "label": REPORT_CATEGORIES[category]["label"],
            **cat_summary,
        }
        items.extend(cat_items)

    last_import = get_last_import(db_path)
    hostname = ""
    if last_import:
        hostname = last_import["hostname"] or ""
        if last_import["domain"]:
            hostname = f"{hostname}.{last_import['domain']}" if hostname else last_import["domain"]

    settings = get_report_settings(db_path)
    logo_path = get_logo_path(db_path, branding_folder)

    return {
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "hostname": hostname,
            "fmtool_version": FMTOOL_VERSION,
            "scope": scope,
            "mode": mode,
            "date_from": date_from,
            "date_to": date_to,
            "company_name": settings["company_name"],
            "report_title": settings["report_title"],
            "logo_path": logo_path,
        },
        "summary": {
            "global": global_summary,
            "per_category": per_category_summary,
        },
        "items": items,
    }


# -- CSV generation --


CSV_HEADER = [
    "category", "item_name", "item_type", "status",
    "sophos_objects", "last_action_at", "error_message",
]


def generate_csv(report_data):
    """Generate CSV bytes from a report_data dict. Includes a small meta preamble."""
    buf = io.StringIO()
    # UTF-8 BOM so Excel opens it correctly
    buf.write("\ufeff")

    meta = report_data["meta"]
    summary = report_data["summary"]["global"]

    # Preamble lines prefixed with '#' so they're easy to skip programmatically
    preamble = [
        ["# FMTool Migration Report"],
        ["# Generated at", meta["generated_at"]],
        ["# Firewall", meta["hostname"] or "(unknown)"],
        ["# Scope", meta["scope"]],
        ["# Mode", meta["mode"]],
    ]
    if meta["mode"] == "range":
        preamble.append(["# Date range", f"{meta['date_from']} – {meta['date_to']}"])
    if meta["company_name"]:
        preamble.append(["# Company", meta["company_name"]])
    preamble.append([
        "# Totals",
        f"total={summary['total']}",
        f"migrated={summary['migrated']}",
        f"skipped={summary['skipped']}",
        f"failed={summary['failed']}",
        f"pending={summary['pending']}",
    ])
    preamble.append([])  # blank line

    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    for line in preamble:
        writer.writerow(line)

    writer.writerow(CSV_HEADER)
    for item in report_data["items"]:
        writer.writerow([
            item["category"],
            item["item_name"],
            item["item_type"],
            item["status"],
            "|".join(item["sophos_objects"]),
            item["last_action_at"],
            item["error_message"],
        ])

    return buf.getvalue().encode("utf-8")


# -- PDF generation (reportlab) --


def generate_pdf(report_data):
    """Generate PDF bytes from a report_data dict."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Image,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="FMTool Migration Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], alignment=0, fontSize=20, spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], fontSize=11,
        textColor=colors.HexColor("#555555"), spaceAfter=14
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontSize=14, spaceBefore=8, spaceAfter=6
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["Normal"], fontSize=8, leading=10
    )
    cell_style = ParagraphStyle(
        "Cell", parent=styles["Normal"], fontSize=8, leading=10
    )

    story = []
    meta = report_data["meta"]
    summary_global = report_data["summary"]["global"]
    per_category = report_data["summary"]["per_category"]

    # --- Header: logo + title ---
    header_cells = []
    title_cell = [
        Paragraph(meta["report_title"] or "Migration Report", title_style),
    ]
    if meta["company_name"]:
        title_cell.append(Paragraph(meta["company_name"], subtitle_style))
    else:
        title_cell.append(Spacer(1, 6))

    logo_flowable = Spacer(1, 1)
    if meta["logo_path"] and os.path.exists(meta["logo_path"]):
        try:
            # Pre-validate by fully loading via PIL so a corrupt file fails here
            # rather than at reportlab draw time (which crashes the build).
            from PIL import Image as PILImage
            with PILImage.open(meta["logo_path"]) as pil_img:
                pil_img.load()
            logo_flowable = Image(meta["logo_path"], width=40 * mm, height=20 * mm, kind="proportional")
        except Exception:
            logo_flowable = Spacer(1, 1)

    header_table = Table(
        [[title_cell, logo_flowable]],
        colWidths=[120 * mm, 50 * mm],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 6 * mm))

    # --- Metadata table ---
    meta_rows = [
        ["Generated at", meta["generated_at"]],
        ["Source firewall", meta["hostname"] or "(unknown)"],
        ["FMTool version", f"v{meta['fmtool_version']}"],
        ["Scope", meta["scope"]],
        ["Mode", meta["mode"]],
    ]
    if meta["mode"] == "range":
        meta_rows.append(["Date range", f"{meta['date_from']} – {meta['date_to']}"])

    meta_table = Table(meta_rows, colWidths=[40 * mm, 130 * mm])
    meta_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f2f2f2")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8 * mm))

    # --- Executive summary ---
    story.append(Paragraph("Executive Summary", section_style))

    summary_rows = [["Category", "Total", "Migrated", "Skipped", "Failed", "Pending"]]
    summary_rows.append([
        "All", str(summary_global["total"]), str(summary_global["migrated"]),
        str(summary_global["skipped"]), str(summary_global["failed"]),
        str(summary_global["pending"]),
    ])
    for cat_key, cat_data in per_category.items():
        summary_rows.append([
            cat_data["label"],
            str(cat_data["total"]),
            str(cat_data["migrated"]),
            str(cat_data["skipped"]),
            str(cat_data["failed"]),
            str(cat_data["pending"]),
        ])

    summary_table = Table(summary_rows, colWidths=[55 * mm, 20 * mm, 24 * mm, 22 * mm, 20 * mm, 24 * mm])
    summary_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#eef6ff")),
        ("FONT", (0, 1), (-1, 1), "Helvetica-Bold", 9),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#999999")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        # Color accents for migrated/skipped/failed/pending columns
        ("TEXTCOLOR", (2, 1), (2, -1), colors.HexColor("#1b7f3a")),
        ("TEXTCOLOR", (3, 1), (3, -1), colors.HexColor("#666666")),
        ("TEXTCOLOR", (4, 1), (4, -1), colors.HexColor("#b00020")),
        ("TEXTCOLOR", (5, 1), (5, -1), colors.HexColor("#a07100")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6 * mm))

    # --- Per-category detail sections ---
    scope = meta["scope"]
    category_list = GLOBAL_SCOPE_CATEGORIES if scope == "global" else [scope]

    for idx, category in enumerate(category_list):
        cat_items = [i for i in report_data["items"] if i["category"] == category]
        if scope == "global":
            story.append(PageBreak())
        else:
            story.append(Spacer(1, 6 * mm))

        label = REPORT_CATEGORIES[category]["label"]
        story.append(Paragraph(label, section_style))

        if not cat_items:
            story.append(Paragraph("No items in this category.", small_style))
            continue

        # Group by status
        grouped = {s: [] for s in STATUS_ORDER}
        for it in cat_items:
            grouped.setdefault(it["status"], grouped.get(it["status"], [])).append(it)

        any_rendered = False
        for status in STATUS_ORDER:
            group = grouped.get(status) or []
            if not group:
                continue
            any_rendered = True
            story.append(Spacer(1, 3 * mm))
            story.append(Paragraph(
                f"<b>{status.capitalize()}</b> &nbsp; ({len(group)})",
                ParagraphStyle("StatusHeader", parent=styles["Normal"], fontSize=10,
                               textColor=_status_color(colors, status), spaceAfter=2)
            ))

            rows = [["Item", "Type", "Sophos objects", "Timestamp", "Error"]]
            for it in group:
                sophos_cell = "<br/>".join(it["sophos_objects"]) if it["sophos_objects"] else "—"
                err_cell = it["error_message"] or ""
                rows.append([
                    Paragraph(_escape(it["item_name"]), cell_style),
                    Paragraph(_escape(it["item_type"] or ""), cell_style),
                    Paragraph(sophos_cell, cell_style),
                    Paragraph(_escape(it["last_action_at"] or ""), cell_style),
                    Paragraph(_escape(err_cell), cell_style),
                ])

            tbl = Table(
                rows,
                colWidths=[38 * mm, 22 * mm, 55 * mm, 28 * mm, 27 * mm],
                repeatRows=1,
            )
            tbl.setStyle(TableStyle([
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
                ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#dddddd")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(tbl)

        if not any_rendered:
            story.append(Paragraph("No items in this category.", small_style))

    # Footer callback
    def _on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#888888"))
        footer = f"Generated by FMTool v{FMTOOL_VERSION}   ·   Page {doc_.page}"
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, footer)
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


def _status_color(colors, status):
    return {
        "migrated": colors.HexColor("#1b7f3a"),
        "failed": colors.HexColor("#b00020"),
        "skipped": colors.HexColor("#666666"),
        "pending": colors.HexColor("#a07100"),
    }.get(status, colors.black)


def _escape(text):
    """Escape text for use inside a reportlab Paragraph."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_filename(scope, ext):
    """Standardized export filename."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"fmtool_report_{scope}_{ts}.{ext}"
