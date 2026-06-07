import json
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
from core.aggregator import aggregate

C_CRITICAL = colors.HexColor("#D32F2F")
C_HIGH = colors.HexColor("#F57C00")
C_MEDIUM = colors.HexColor("#F9A825")
C_INFO = colors.HexColor("#1976D2")
C_DARK = colors.HexColor("#1A1A2E")
C_LIGHT = colors.HexColor("#F5F5F5")
C_WHITE = colors.white
C_ACCENT = colors.HexColor("#0D47A1")
SEV_COLOUR = {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH, "MEDIUM": C_MEDIUM, "INFO": C_INFO}

def safe(val):
    return str(val) if val is not None else "—"

def json_safe(val):
    try:
        return json.loads(val) if val else []
    except Exception:
        return []

def make_styles():
    styles = {}
    styles["title"] = ParagraphStyle("title", fontSize=26, fontName="Helvetica-Bold", textColor=C_WHITE, alignment=TA_CENTER, spaceAfter=8)
    styles["section"] = ParagraphStyle("section", fontSize=13, fontName="Helvetica-Bold", textColor=C_ACCENT, spaceBefore=12, spaceAfter=6)
    styles["body"] = ParagraphStyle("body", fontSize=9, fontName="Helvetica", textColor=colors.HexColor("#333333"), spaceAfter=4, leading=13)
    styles["small"] = ParagraphStyle("small", fontSize=8, fontName="Helvetica", textColor=colors.HexColor("#444444"), leading=11)
    styles["bold"] = ParagraphStyle("bold", fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#111111"))
    return styles

def cover_page(target, report, styles):
    elements = []
    hdr = Table([[Paragraph("OSINT Security Report", styles["title"])]], colWidths=[17*cm])
    hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_DARK),("TOPPADDING",(0,0),(-1,-1),36),("BOTTOMPADDING",(0,0),(-1,-1),36),("LEFTPADDING",(0,0),(-1,-1),20),("RIGHTPADDING",(0,0),(-1,-1),20)]))
    elements.append(hdr)
    elements.append(Spacer(1, 0.4*cm))
    elements.append(Paragraph(f"Target: <b>{target}</b>", ParagraphStyle("ct", fontSize=15, fontName="Helvetica", textColor=C_ACCENT, alignment=TA_CENTER)))
    elements.append(Paragraph(f"Generated: {report['generated_at']}", ParagraphStyle("cd", fontSize=10, fontName="Helvetica", textColor=colors.grey, alignment=TA_CENTER, spaceAfter=16)))
    elements.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=16))
    sm = report["summary"]
    box_data = [[
        Paragraph(f"<b>{sm['critical']}</b><br/>CRITICAL", ParagraphStyle("b1", fontSize=16, fontName="Helvetica-Bold", textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph(f"<b>{sm['high']}</b><br/>HIGH", ParagraphStyle("b2", fontSize=16, fontName="Helvetica-Bold", textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph(f"<b>{sm['medium']}</b><br/>MEDIUM", ParagraphStyle("b3", fontSize=16, fontName="Helvetica-Bold", textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph(f"<b>{sm['info']}</b><br/>INFO", ParagraphStyle("b4", fontSize=16, fontName="Helvetica-Bold", textColor=C_WHITE, alignment=TA_CENTER)),
    ]]
    bt = Table(box_data, colWidths=[4*cm]*4)
    bt.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),C_CRITICAL),("BACKGROUND",(1,0),(1,0),C_HIGH),("BACKGROUND",(2,0),(2,0),C_MEDIUM),("BACKGROUND",(3,0),(3,0),C_INFO),("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14),("ALIGN",(0,0),(-1,-1),"CENTER")]))
    elements.append(bt)
    elements.append(Spacer(1, 0.4*cm))
    live = sum(1 for x in report["subdomains"] if x.get("status") == "live")
    sd = [[Paragraph(f"Subdomains: <b>{len(report['subdomains'])}</b> ({live} live)", styles["body"]), Paragraph(f"Open Ports: <b>{len(report['ports'])}</b>", styles["body"]), Paragraph(f"Emails: <b>{len(report['emails'])}</b>", styles["body"]), Paragraph(f"Total Findings: <b>{sm['total']}</b>", styles["body"])]]
    st2 = Table(sd, colWidths=[4.25*cm]*4)
    st2.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_LIGHT),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7),("ALIGN",(0,0),(-1,-1),"CENTER"),("BOX",(0,0),(-1,-1),0.5,colors.lightgrey)]))
    elements.append(st2)
    elements.append(PageBreak())
    return elements

def findings_table(report, styles):
    elements = []
    elements.append(Paragraph("Security Findings", styles["section"]))
    elements.append(Paragraph(f"Total findings: {report['summary']['total']} | Sorted by severity", styles["body"]))
    elements.append(Spacer(1, 0.2*cm))
    if not report["findings"]:
        elements.append(Paragraph("No findings recorded.", styles["body"]))
        return elements
    data = [[Paragraph("<b>Severity</b>", styles["bold"]), Paragraph("<b>Category</b>", styles["bold"]), Paragraph("<b>Host</b>", styles["bold"]), Paragraph("<b>Detail</b>", styles["bold"])]]
    row_styles = []
    for i, f in enumerate(report["findings"], 1):
        sev = f.get("severity", "INFO")
        col = SEV_COLOUR.get(sev, C_INFO)
        data.append([
            Paragraph(f'<font color="{col.hexval()}"><b>{sev}</b></font>', styles["small"]),
            Paragraph(safe(f.get("category",""))[:20], styles["small"]),
            Paragraph(safe(f.get("host",""))[:35], styles["small"]),
            Paragraph(safe(f.get("detail",""))[:80], styles["small"]),
        ])
        bg = colors.HexColor("#FFF3F3") if sev == "CRITICAL" else colors.HexColor("#FFF8F0") if sev == "HIGH" else (C_WHITE if i % 2 == 0 else C_LIGHT)
        row_styles.append(("BACKGROUND",(0,i),(-1,i),bg))
    t = Table(data, colWidths=[2.2*cm, 2.8*cm, 4.5*cm, 7.5*cm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),("FONTSIZE",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#DDDDDD")),("VALIGN",(0,0),(-1,-1),"TOP")] + row_styles))
    elements.append(t)
    elements.append(PageBreak())
    return elements

def subdomains_section(report, styles):
    elements = []
    elements.append(Paragraph("Discovered Subdomains", styles["section"]))
    live = [x for x in report["subdomains"] if x.get("status") == "live"]
    elements.append(Paragraph(f"Total: {len(report['subdomains'])} | Live: {len(live)}", styles["body"]))
    elements.append(Spacer(1, 0.2*cm))
    if not report["subdomains"]:
        elements.append(Paragraph("No subdomains found.", styles["body"]))
        return elements
    data = [[Paragraph("<b>Subdomain</b>", styles["bold"]), Paragraph("<b>IP</b>", styles["bold"]), Paragraph("<b>Status</b>", styles["bold"])]]
    for x in report["subdomains"]:
        sub = safe(x.get("subdomain"))[:45]
        ip  = safe(x.get("ip"))
        st  = safe(x.get("status"))
        col = "green" if st == "live" else "grey"
        data.append([Paragraph(sub, styles["small"]), Paragraph(ip, styles["small"]), Paragraph(f'<font color="{col}">{st}</font>', styles["small"])])
    t = Table(data, colWidths=[8*cm, 4*cm, 3*cm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),("FONTSIZE",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("GRID",(0,0),(-1,-1),0.3,colors.lightgrey),("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT])]))
    elements.append(t)
    elements.append(PageBreak())
    return elements

def ports_section(report, styles):
    elements = []
    elements.append(Paragraph("Open Ports & Services", styles["section"]))
    elements.append(Paragraph(f"Total open ports: {len(report['ports'])}", styles["body"]))
    elements.append(Spacer(1, 0.2*cm))
    if not report["ports"]:
        elements.append(Paragraph("No open ports recorded.", styles["body"]))
        return elements
    data = [[Paragraph("<b>IP</b>", styles["bold"]), Paragraph("<b>Port</b>", styles["bold"]), Paragraph("<b>Service</b>", styles["bold"]), Paragraph("<b>Version</b>", styles["bold"]), Paragraph("<b>CVEs</b>", styles["bold"])]]
    for p in report["ports"]:
        cvelist = json_safe(p.get("vulns","[]"))
        cvestr  = f"{len(cvelist)} CVEs" if cvelist else "None"
        cvecol  = f'<font color="red"><b>{cvestr}</b></font>' if cvelist else cvestr
        data.append([Paragraph(safe(p.get("ip"))[:16], styles["small"]), Paragraph(safe(p.get("port")), styles["small"]), Paragraph(safe(p.get("service"))[:12], styles["small"]), Paragraph(safe(p.get("version"))[:25], styles["small"]), Paragraph(cvecol, styles["small"])])
    t = Table(data, colWidths=[3.5*cm, 2*cm, 2.5*cm, 5.5*cm, 2.5*cm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),("FONTSIZE",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("GRID",(0,0),(-1,-1),0.3,colors.lightgrey),("ROWBACKGROUNDS",(0,1),(-1,-1),[C_WHITE,C_LIGHT])]))
    elements.append(t)
    elements.append(PageBreak())
    return elements

def whois_section(report, styles):
    elements = []
    elements.append(Paragraph("WHOIS Registration Data", styles["section"]))
    w = report.get("whois", {})
    if not w:
        elements.append(Paragraph("No WHOIS data collected.", styles["body"]))
        return elements
    rows = [["Registrar", safe(w.get("registrar"))], ["Organisation", safe(w.get("org"))], ["Created", safe(w.get("creation_date"))], ["Expires", safe(w.get("expiration_date"))], ["Name Servers", safe(w.get("name_servers"))[:60]]]
    t = Table([[Paragraph(f"<b>{r[0]}</b>", styles["bold"]), Paragraph(r[1][:70], styles["small"])] for r in rows], colWidths=[4*cm, 13*cm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),C_LIGHT),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),("GRID",(0,0),(-1,-1),0.3,colors.lightgrey)]))
    elements.append(t)
    return elements

def generate_pdf(target, conn, output_path):
    print(f"[*] Aggregating findings for {target}...")
    report = aggregate(target)
    print(f"[*] Building PDF -> {output_path}...")
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=1.5*cm, leftMargin=1.5*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = make_styles()
    elements = []
    elements += cover_page(target, report, styles)
    elements += findings_table(report, styles)
    elements += subdomains_section(report, styles)
    elements += ports_section(report, styles)
    elements += whois_section(report, styles)
    doc.build(elements)
    print(f"[+] PDF saved -> {output_path}")
    print(f"[+] Findings: {report['summary']['total']} | Critical: {report['summary']['critical']} | High: {report['summary']['high']}")
