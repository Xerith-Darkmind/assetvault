"""Unencrypted CSV and insurance PDF exports. Written only via av.write_export.

Photo bytes are decrypted in memory. The redacted PDF masks serials to the
last 4 characters and omits receipt names.
"""
import csv, io, secrets
from xml.sax.saxutils import escape

import avcore as av
import avlogic as lg

def _stamp():
    import datetime
    return datetime.datetime.now(av.TZ).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)

def _cell(value):
    if value is None:
        return ""
    text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text

def _rows(key):
    con = av.open_db(key)
    try:
        cols = [r[1] for r in con.execute("PRAGMA table_info(items)")]
        items = [dict(r) for r in con.execute("SELECT * FROM items ORDER BY room, category, name COLLATE NOCASE, id")]
        links = {}
        for row in con.execute(
            "SELECT i.item_id, i.not_seen_at, s.name FROM item_sources i JOIN sources s ON s.id=i.source_id ORDER BY s.name"
        ):
            links.setdefault(row["item_id"], []).append(dict(row))
        photos = {}
        for item in items:
            for ref in lg.refs(item.get("photo_refs"))[:3]:
                if ref["id"] in photos:
                    continue
                try:
                    photos[ref["id"]] = av.get_blob(key, ref["id"])
                except Exception:
                    photos[ref["id"]] = None
        return cols, items, links, photos
    finally:
        con.close()

def build_csv(key):
    cols, items, links, _photos = _rows(key)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(cols + ["linked_sources", "not_seen_at"])
    for item in items:
        linked = links.get(item["id"], [])
        linked_names = "; ".join("" if row["name"] is None else str(row["name"]) for row in linked)
        missed = "; ".join(row["not_seen_at"] for row in linked if row["not_seen_at"])
        writer.writerow([_cell(item.get(col)) for col in cols] + [_cell(linked_names), _cell(missed)])
    name = "inventory-%s.csv" % _stamp()
    return name, buf.getvalue().encode("utf-8"), len(items)

def _money(value):
    if value in (None, ""):
        return "-"
    return f"{float(value):,.2f}"

def _text(value):
    text = "" if value is None else str(value).strip()
    return text or "-"

def _groups(items, key):
    groups = {}
    for item in items:
        label = item.get(key) or "(none)"
        bucket = groups.setdefault(label, {"count": 0, "purchase": 0.0, "replacement": 0.0})
        bucket["count"] += 1
        bucket["purchase"] += float(item.get("purchase_price") or 0)
        bucket["replacement"] += float(item.get("replacement_value") or 0)
    return groups

def _thumb(blob):
    if not blob:
        return None
    try:
        from PIL import Image as PILImage
        image = PILImage.open(io.BytesIO(blob))
        image.verify()
    except Exception:
        return None
    from reportlab.platypus import Image
    bio = io.BytesIO(blob)
    try:
        return Image(bio, width=36, height=36, kind="proportional", lazy=2, hAlign="LEFT"), bio
    except Exception:
        return None

def build_pdf(key, redacted=False):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    _cols, items, _links, photos = _rows(key)
    tiny = ParagraphStyle("av", fontName="Helvetica", fontSize=8, leading=10, textColor=colors.HexColor("#1c2830"))
    title = ParagraphStyle("avt", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=colors.HexColor("#102028"))
    head = ParagraphStyle("avh", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#102028"))
    body = ParagraphStyle("avb", fontName="Helvetica", fontSize=9, leading=12, textColor=colors.HexColor("#1c2830"))
    warn = ParagraphStyle("avw", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.HexColor("#8a1c2b"))

    def P(text, style=tiny):
        return Paragraph(escape(_text(text)), style)

    story = [Paragraph("AssetVault insurance schedule", title), Spacer(1, 6)]
    if redacted:
        story.append(Paragraph("REDACTED COPY. Serial numbers show only the last 4 characters. Receipts are omitted.", warn))
    story.append(Paragraph("This file is not encrypted. It contains inventory data in the clear.", warn))
    story.append(Spacer(1, 8))
    purchase = sum(float(i.get("purchase_price") or 0) for i in items)
    replace = sum(float(i.get("replacement_value") or 0) for i in items)
    story.append(Paragraph(
        "Generated %s. %d items. Purchase total %s. Replacement total %s."
        % (av.now(), len(items), _money(purchase), _money(replace)),
        body,
    ))
    story.append(Spacer(1, 10))
    held = []

    def group_table(label, groups):
        data = [[P(h, head) for h in (label, "Count", "Purchase", "Replacement")]]
        for name in sorted(groups, key=lambda s: s.casefold()):
            bucket = groups[name]
            data.append([P(name), P(str(bucket["count"])), P(_money(bucket["purchase"])), P(_money(bucket["replacement"]))])
        table = Table(data, colWidths=[260, 70, 120, 120], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102028")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ced6")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ]))
        return table

    story.append(Paragraph("Totals by room", head))
    story.append(Spacer(1, 4))
    story.append(group_table("Room", _groups(items, "room")))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Totals by category", head))
    story.append(Spacer(1, 4))
    story.append(group_table("Category", _groups(items, "category")))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Devices", head))
    story.append(Spacer(1, 4))
    headers = ["Name", "Room", "Category", "Brand", "Model", "Serial", "Condition", "Purchase", "Replacement", "Photo"]
    if not redacted:
        headers.append("Receipts")
    data = [[P(h, head) for h in headers]]
    for item in items:
        serial = lg.mask_serial(item.get("serial"), mark="****") if redacted else _text(item.get("serial"))
        photo = P("-")
        for ref in lg.refs(item.get("photo_refs"))[:3]:
            made = _thumb(photos.get(ref["id"]))
            if made:
                flow, bio = made
                held.append(bio)
                photo = flow
                break
        row = [
            P(item.get("name")), P(item.get("room")), P(item.get("category")), P(item.get("brand")),
            P(item.get("model")), P(serial), P(item.get("condition")), P(_money(item.get("purchase_price"))),
            P(_money(item.get("replacement_value"))), photo,
        ]
        if not redacted:
            names = [ref.get("name") or ref.get("id") for ref in lg.refs(item.get("receipt_refs"))]
            row.append(P(", ".join(names) if names else "-"))
        data.append(row)
    widths = [78, 58, 62, 52, 62, 78, 52, 58, 64, 48]
    if not redacted:
        widths.append(70)
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102028")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ced6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
    ]))
    story.append(table)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#5c6b76"))
        label = "AssetVault insurance schedule — unencrypted export"
        if redacted:
            label += " — redacted"
        canvas.drawString(36, 22, label)
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=landscape(letter), leftMargin=28, rightMargin=28, topMargin=32, bottomMargin=36,
        title="AssetVault insurance schedule", author="AssetVault", pageCompression=0,
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    held.clear()
    filename = ("insurance-redacted-%s.pdf" if redacted else "insurance-%s.pdf") % _stamp()
    return filename, buf.getvalue(), len(items)
