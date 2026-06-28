#!/usr/bin/env python3
"""
Phishing Email Forensics — Report Generator
=============================================
Génère des rapports d'incident SOC en PDF et DOCX
à partir des données d'analyse phishing.
"""

import io
import os
from datetime import datetime


def generate_pdf_report(analysis: dict) -> bytes:
    """Génère un rapport PDF d'incident SOC. Retourne les bytes du PDF."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            topMargin=20*mm, bottomMargin=20*mm,
                            leftMargin=20*mm, rightMargin=20*mm)

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        'ReportTitle', parent=styles['Title'],
        fontSize=22, textColor=HexColor('#1a1a1a'),
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        'SectionTitle', parent=styles['Heading2'],
        fontSize=14, textColor=HexColor('#2c3e50'),
        spaceBefore=16, spaceAfter=8,
        borderWidth=1, borderColor=HexColor('#bdc3c7'),
        borderPadding=4
    ))
    styles.add(ParagraphStyle(
        'SubSection', parent=styles['Heading3'],
        fontSize=11, textColor=HexColor('#34495e'),
        spaceBefore=10, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        'BodyText2', parent=styles['Normal'],
        fontSize=9, leading=13, textColor=HexColor('#333333')
    ))
    styles.add(ParagraphStyle(
        'SmallMono', parent=styles['Normal'],
        fontSize=8, fontName='Courier', textColor=HexColor('#555555'),
        leading=11
    ))

    story = []
    meta = analysis.get("metadata", {})
    verdict = analysis.get("verdict", {})
    auth = analysis.get("authentication", {})
    iocs = analysis.get("iocs", {})
    atts = analysis.get("attachments", [])
    risk = analysis.get("risk_scoring", {})
    ai = analysis.get("ai_analysis", {})
    headers_a = analysis.get("headers_analysis", {})

    score = verdict.get("score", 0)
    level = verdict.get("risk_level", "INFO")
    now = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── HEADER ──
    story.append(Paragraph("RAPPORT D'INCIDENT PHISHING", styles['ReportTitle']))
    story.append(Paragraph(f"SOC Analysis Report — {now}", styles['BodyText2']))
    story.append(Spacer(1, 4*mm))

    # Severity banner
    level_colors = {
        'CRITICAL': '#e74c3c', 'HIGH': '#e67e22',
        'MEDIUM': '#3498db', 'LOW': '#27ae60', 'INFO': '#95a5a6'
    }
    color = level_colors.get(level, '#95a5a6')
    story.append(Paragraph(
        f'<font color="{color}" size="16"><b>Severite: {level} — Score: {score}/100</b></font>',
        styles['Normal']
    ))
    story.append(Spacer(1, 2*mm))
    if verdict.get("summary"):
        story.append(Paragraph(f'<i>{_safe(verdict["summary"])}</i>', styles['BodyText2']))
    story.append(Spacer(1, 4*mm))

    # ── 1. RESUME INCIDENT ──
    story.append(Paragraph("1. RESUME DE L'INCIDENT", styles['SectionTitle']))
    incident_data = [
        ["Date du rapport", now],
        ["Sujet de l'email", _safe(meta.get("subject", "N/A"))],
        ["Expediteur", _safe(meta.get("from", "N/A"))],
        ["Destinataire", _safe(meta.get("to", "N/A"))],
        ["Date de reception", _safe(meta.get("date", "N/A"))],
        ["Message-ID", _safe(meta.get("message_id", "N/A"))],
        ["Score de risque", f"{score}/100 ({level})"],
    ]
    t = Table(incident_data, colWidths=[45*mm, 115*mm])
    t.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#2c3e50')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8f9fa')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # ── 2. AUTHENTIFICATION ──
    story.append(Paragraph("2. VERIFICATION D'AUTHENTIFICATION", styles['SectionTitle']))
    auth_data = [["Protocole", "Statut", "Details"]]
    for proto in ['spf', 'dkim', 'dmarc']:
        item = auth.get(proto, {})
        status = item.get("status", "absent").upper()
        details = _safe(item.get("details", ""))[:80]
        auth_data.append([proto.upper(), status, details])

    t = Table(auth_data, colWidths=[25*mm, 25*mm, 110*mm])
    t.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    # Color code status cells
    for i, proto in enumerate(['spf', 'dkim', 'dmarc'], 1):
        status = auth.get(proto, {}).get("status", "absent")
        if status == "pass":
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), HexColor('#27ae60'))]))
        elif status in ("fail", "softfail"):
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), HexColor('#e74c3c'))]))
    story.append(t)

    # ── 3. IOCs ──
    story.append(Paragraph("3. INDICATEURS DE COMPROMISSION (IOCs)", styles['SectionTitle']))

    urls = iocs.get("urls", [])
    if urls:
        story.append(Paragraph("3.1 URLs detectees", styles['SubSection']))
        url_data = [["URL", "Flags"]]
        for u in urls:
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("Shortener")
            if u.get("mismatched_display"): flags.append("Lien trompeur")
            url_data.append([_safe(u.get("url", ""))[:70], ", ".join(flags) or "OK"])

        t = Table(url_data, colWidths=[110*mm, 50*mm])
        t.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t)

    ips = iocs.get("ips", [])
    if ips:
        story.append(Paragraph("3.2 Adresses IP", styles['SubSection']))
        for ip_info in ips:
            story.append(Paragraph(f"&bull; {ip_info.get('ip', 'N/A')} (privee: {ip_info.get('is_private', False)})", styles['BodyText2']))

    kws = iocs.get("phishing_keywords", [])
    if kws:
        story.append(Paragraph("3.3 Mots-cles phishing detectes", styles['SubSection']))
        story.append(Paragraph(", ".join(kws), styles['BodyText2']))

    # ── 4. PIECES JOINTES ──
    if atts:
        story.append(Paragraph("4. PIECES JOINTES", styles['SectionTitle']))
        att_data = [["Fichier", "Type", "Taille", "Suspect", "MD5"]]
        for att in atts:
            att_data.append([
                _safe(att.get("filename", "")),
                _safe(att.get("content_type", "")),
                _format_bytes(att.get("size_bytes", 0)),
                "OUI" if att.get("suspicious_extension") else "Non",
                att.get("md5", "")[:16] + "..."
            ])
        t = Table(att_data, colWidths=[40*mm, 35*mm, 20*mm, 18*mm, 47*mm])
        t.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t)

    # ── 5. FACTEURS DE RISQUE ──
    factors = risk.get("factors", [])
    if factors:
        story.append(Paragraph("5. FACTEURS DE RISQUE", styles['SectionTitle']))
        for f in factors:
            story.append(Paragraph(f"&bull; {_safe(f)}", styles['BodyText2']))

    # ── 6. ANOMALIES ──
    anomalies = headers_a.get("anomalies", [])
    if anomalies:
        story.append(Paragraph("6. ANOMALIES DE HEADERS", styles['SectionTitle']))
        for a in anomalies:
            story.append(Paragraph(f"&bull; {_safe(a)}", styles['BodyText2']))

    # ── 7. ANALYSE IA ──
    if ai and not ai.get("error"):
        story.append(PageBreak())
        story.append(Paragraph("7. ANALYSE IA — SOCIAL ENGINEERING", styles['SectionTitle']))

        sem = ai.get("semantic_analysis", {})
        imp = ai.get("impersonation", {})
        soph = ai.get("sophistication", {})

        ai_data = [
            ["Emotion ciblee", _safe(sem.get("target_emotion", "N/A"))],
            ["Pretexte", _safe(sem.get("pretext", imp.get("pretext", "N/A")))],
            ["Entite usurpee", _safe(imp.get("impersonated_entity", "N/A"))],
            ["Qualite usurpation", f"{imp.get('impersonation_quality', 'N/A')}/10"],
            ["Credibilite", f"{sem.get('credibility_assessment', 'N/A')}/10"],
            ["Sophistication", f"{soph.get('level', 'N/A')} ({soph.get('score', 'N/A')}/10)"],
            ["Confiance IA", f"{round((ai.get('ai_confidence', 0)) * 100)}%"],
        ]
        t = Table(ai_data, colWidths=[45*mm, 115*mm])
        t.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#2c3e50')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8f9fa')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)

        # Tactics
        tactics = ai.get("social_engineering_tactics", [])
        if tactics:
            story.append(Paragraph("7.1 Tactiques de manipulation", styles['SubSection']))
            tac_data = [["Tactique", "Principe Cialdini", "Efficacite"]]
            for tac in tactics:
                tac_data.append([
                    _safe(tac.get("tactic", "")),
                    _safe(tac.get("cialdini_principle", "")),
                    _safe(tac.get("effectiveness", "")).upper()
                ])
            t = Table(tac_data, colWidths=[40*mm, 70*mm, 50*mm])
            t.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(t)

        # MITRE
        mitre = ai.get("mitre_techniques", [])
        if mitre:
            story.append(Paragraph("7.2 Mapping MITRE ATT&CK", styles['SubSection']))
            mitre_data = [["ID", "Technique", "Pertinence"]]
            for m in mitre:
                mitre_data.append([m.get("id", ""), _safe(m.get("name", "")), _safe(m.get("relevance", ""))[:60]])
            t = Table(mitre_data, colWidths=[25*mm, 55*mm, 80*mm])
            t.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(t)

        # Executive summary
        if ai.get("executive_summary"):
            story.append(Paragraph("7.3 Resume executif", styles['SubSection']))
            story.append(Paragraph(_safe(ai["executive_summary"]), styles['BodyText2']))

    # ── 8. RECOMMANDATIONS ──
    recs = ai.get("recommended_actions", []) if ai else []
    rec_from_verdict = verdict.get("recommendation", "")
    if recs or rec_from_verdict:
        story.append(Paragraph("8. ACTIONS RECOMMANDEES", styles['SectionTitle']))
        if recs:
            for i, r in enumerate(recs, 1):
                story.append(Paragraph(f"{i}. {_safe(r)}", styles['BodyText2']))
        elif rec_from_verdict:
            for line in rec_from_verdict.split("\n"):
                if line.strip():
                    story.append(Paragraph(_safe(line.strip()), styles['BodyText2']))

    # ── FOOTER ──
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph(
        f'<font color="#999999" size="8">Rapport genere par Phishing Email Forensics — {now} — Confidentiel</font>',
        styles['Normal']
    ))

    doc.build(story)
    return buf.getvalue()


def generate_docx_report(analysis: dict) -> bytes:
    """Génère un rapport DOCX d'incident SOC. Retourne les bytes du DOCX."""
    from docx import Document
    from docx.shared import Inches, Pt, Cm, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT

    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.5)

    meta = analysis.get("metadata", {})
    verdict = analysis.get("verdict", {})
    auth = analysis.get("authentication", {})
    iocs = analysis.get("iocs", {})
    atts = analysis.get("attachments", [])
    risk = analysis.get("risk_scoring", {})
    ai = analysis.get("ai_analysis", {})
    headers_a = analysis.get("headers_analysis", {})

    score = verdict.get("score", 0)
    level = verdict.get("risk_level", "INFO")
    now = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── TITLE ──
    title = doc.add_heading("RAPPORT D'INCIDENT PHISHING", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = subtitle.add_run(f"SOC Analysis Report — {now}")
    run.font.size = Pt(11)
    run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

    # Severity
    sev = doc.add_paragraph()
    sev.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = sev.add_run(f"SEVERITE: {level} — SCORE: {score}/100")
    run.font.size = Pt(16)
    run.bold = True
    level_colors = {
        'CRITICAL': RGBColor(0xe7, 0x4c, 0x3c), 'HIGH': RGBColor(0xe6, 0x7e, 0x22),
        'MEDIUM': RGBColor(0x34, 0x98, 0xdb), 'LOW': RGBColor(0x27, 0xae, 0x60),
    }
    run.font.color.rgb = level_colors.get(level, RGBColor(0x95, 0xa5, 0xa6))

    if verdict.get("summary"):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(verdict["summary"])
        run.italic = True
        run.font.size = Pt(10)

    # ── 1. RESUME ──
    doc.add_heading("1. Resume de l'incident", level=1)
    table = doc.add_table(rows=7, cols=2)
    table.style = 'Light Grid Accent 1'
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    rows_data = [
        ("Date du rapport", now),
        ("Sujet", meta.get("subject", "N/A")),
        ("Expediteur", meta.get("from", "N/A")),
        ("Destinataire", meta.get("to", "N/A")),
        ("Date reception", meta.get("date", "N/A")),
        ("Message-ID", meta.get("message_id", "N/A")),
        ("Score de risque", f"{score}/100 ({level})"),
    ]
    for i, (label, value) in enumerate(rows_data):
        table.rows[i].cells[0].text = label
        table.rows[i].cells[1].text = str(value or "N/A")
        table.rows[i].cells[0].paragraphs[0].runs[0].bold = True if table.rows[i].cells[0].paragraphs[0].runs else None

    # ── 2. AUTHENTIFICATION ──
    doc.add_heading("2. Verification d'authentification", level=1)
    table = doc.add_table(rows=4, cols=3)
    table.style = 'Light Grid Accent 1'
    table.rows[0].cells[0].text = "Protocole"
    table.rows[0].cells[1].text = "Statut"
    table.rows[0].cells[2].text = "Details"
    for cell in table.rows[0].cells:
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True

    for i, proto in enumerate(['spf', 'dkim', 'dmarc'], 1):
        item = auth.get(proto, {})
        table.rows[i].cells[0].text = proto.upper()
        table.rows[i].cells[1].text = item.get("status", "absent").upper()
        table.rows[i].cells[2].text = (item.get("details", "") or "")[:80]

    # ── 3. IOCs ──
    doc.add_heading("3. Indicateurs de compromission (IOCs)", level=1)

    urls = iocs.get("urls", [])
    if urls:
        doc.add_heading("3.1 URLs detectees", level=2)
        table = doc.add_table(rows=len(urls) + 1, cols=2)
        table.style = 'Light Grid Accent 1'
        table.rows[0].cells[0].text = "URL"
        table.rows[0].cells[1].text = "Flags"
        for cell in table.rows[0].cells:
            for p in cell.paragraphs:
                for r in p.runs:
                    r.bold = True
        for i, u in enumerate(urls, 1):
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("Shortener")
            if u.get("mismatched_display"): flags.append("Lien trompeur")
            table.rows[i].cells[0].text = (u.get("url", ""))[:70]
            table.rows[i].cells[1].text = ", ".join(flags) or "OK"

    kws = iocs.get("phishing_keywords", [])
    if kws:
        doc.add_heading("3.2 Mots-cles phishing", level=2)
        doc.add_paragraph(", ".join(kws))

    # ── 4. PIECES JOINTES ──
    if atts:
        doc.add_heading("4. Pieces jointes", level=1)
        table = doc.add_table(rows=len(atts) + 1, cols=4)
        table.style = 'Light Grid Accent 1'
        for j, h in enumerate(["Fichier", "Type", "Suspect", "MD5"]):
            table.rows[0].cells[j].text = h
            for p in table.rows[0].cells[j].paragraphs:
                for r in p.runs:
                    r.bold = True
        for i, att in enumerate(atts, 1):
            table.rows[i].cells[0].text = att.get("filename", "")
            table.rows[i].cells[1].text = att.get("content_type", "")
            table.rows[i].cells[2].text = "OUI" if att.get("suspicious_extension") else "Non"
            table.rows[i].cells[3].text = att.get("md5", "")

    # ── 5. FACTEURS DE RISQUE ──
    factors = risk.get("factors", [])
    if factors:
        doc.add_heading("5. Facteurs de risque", level=1)
        for f in factors:
            doc.add_paragraph(f, style='List Bullet')

    # ── 6. ANOMALIES ──
    anomalies = headers_a.get("anomalies", [])
    if anomalies:
        doc.add_heading("6. Anomalies de headers", level=1)
        for a in anomalies:
            doc.add_paragraph(a, style='List Bullet')

    # ── 7. ANALYSE IA ──
    if ai and not ai.get("error"):
        doc.add_page_break()
        doc.add_heading("7. Analyse IA — Social Engineering", level=1)

        sem = ai.get("semantic_analysis", {})
        imp = ai.get("impersonation", {})
        soph = ai.get("sophistication", {})

        ai_items = [
            ("Emotion ciblee", sem.get("target_emotion", "N/A")),
            ("Pretexte", sem.get("pretext", imp.get("pretext", "N/A"))),
            ("Entite usurpee", imp.get("impersonated_entity", "N/A")),
            ("Sophistication", f"{soph.get('level', 'N/A')} ({soph.get('score', 'N/A')}/10)"),
            ("Confiance IA", f"{round(ai.get('ai_confidence', 0) * 100)}%"),
        ]
        table = doc.add_table(rows=len(ai_items), cols=2)
        table.style = 'Light Grid Accent 1'
        for i, (label, value) in enumerate(ai_items):
            table.rows[i].cells[0].text = label
            table.rows[i].cells[1].text = str(value)

        # Tactics
        tactics = ai.get("social_engineering_tactics", [])
        if tactics:
            doc.add_heading("7.1 Tactiques de manipulation", level=2)
            table = doc.add_table(rows=len(tactics) + 1, cols=3)
            table.style = 'Light Grid Accent 1'
            for j, h in enumerate(["Tactique", "Cialdini", "Efficacite"]):
                table.rows[0].cells[j].text = h
                for p in table.rows[0].cells[j].paragraphs:
                    for r in p.runs:
                        r.bold = True
            for i, tac in enumerate(tactics, 1):
                table.rows[i].cells[0].text = tac.get("tactic", "")
                table.rows[i].cells[1].text = tac.get("cialdini_principle", "")
                table.rows[i].cells[2].text = (tac.get("effectiveness", "")).upper()

        # MITRE
        mitre = ai.get("mitre_techniques", [])
        if mitre:
            doc.add_heading("7.2 Mapping MITRE ATT&CK", level=2)
            table = doc.add_table(rows=len(mitre) + 1, cols=3)
            table.style = 'Light Grid Accent 1'
            for j, h in enumerate(["ID", "Technique", "Pertinence"]):
                table.rows[0].cells[j].text = h
                for p in table.rows[0].cells[j].paragraphs:
                    for r in p.runs:
                        r.bold = True
            for i, m in enumerate(mitre, 1):
                table.rows[i].cells[0].text = m.get("id", "")
                table.rows[i].cells[1].text = m.get("name", "")
                table.rows[i].cells[2].text = m.get("relevance", "")[:60]

        if ai.get("executive_summary"):
            doc.add_heading("7.3 Resume executif", level=2)
            doc.add_paragraph(ai["executive_summary"])

    # ── 8. RECOMMANDATIONS ──
    recs = ai.get("recommended_actions", []) if ai else []
    if recs:
        doc.add_heading("8. Actions recommandees", level=1)
        for i, r in enumerate(recs, 1):
            doc.add_paragraph(f"{i}. {r}")

    # ── FOOTER ──
    doc.add_paragraph("")
    footer = doc.add_paragraph()
    run = footer.add_run(f"Rapport genere par Phishing Email Forensics — {now} — Confidentiel")
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor(0x99, 0x99, 0x99)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _safe(text: str) -> str:
    """Escape text for reportlab XML."""
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format_bytes(b: int) -> str:
    if not b:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"
