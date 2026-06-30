#!/usr/bin/env python3
"""
Phishing Email Forensics — Report Generator
=============================================
Génère des rapports d'incident SOC en PDF et DOCX
à partir des données d'analyse phishing.

Design professionnel avec bannières colorées, icônes textuelles,
mise en page structurée et branding SOC.
"""

import io
import os
from datetime import datetime


def generate_pdf_report(analysis: dict) -> bytes:
    """Génère un rapport PDF d'incident SOC professionnel."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, Color
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, HRFlowable
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics import renderPDF

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            topMargin=15*mm, bottomMargin=18*mm,
                            leftMargin=18*mm, rightMargin=18*mm)

    styles = getSampleStyleSheet()

    # ── Color palette ──
    DARK = HexColor('#1a1a2e')
    PRIMARY = HexColor('#0f3460')
    ACCENT = HexColor('#e94560')
    SUCCESS = HexColor('#27ae60')
    WARNING = HexColor('#f39c12')
    DANGER = HexColor('#e74c3c')
    INFO = HexColor('#3498db')
    LIGHT_BG = HexColor('#f8f9fc')
    BORDER = HexColor('#e2e8f0')
    TEXT_DARK = HexColor('#2d3748')
    TEXT_MUTED = HexColor('#718096')

    level_colors = {
        'CRITICAL': DANGER, 'HIGH': HexColor('#e67e22'),
        'MEDIUM': INFO, 'LOW': SUCCESS, 'INFO': TEXT_MUTED
    }

    # ── Custom styles ──
    styles.add(ParagraphStyle('CoverTitle', parent=styles['Title'],
        fontSize=26, textColor=HexColor('#ffffff'), alignment=TA_CENTER,
        spaceAfter=4, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle('CoverSub', parent=styles['Normal'],
        fontSize=12, textColor=HexColor('#cbd5e0'), alignment=TA_CENTER,
        spaceAfter=2))
    styles.add(ParagraphStyle('SectionNum', parent=styles['Normal'],
        fontSize=13, textColor=PRIMARY, fontName='Helvetica-Bold',
        spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle('SectionTitle', parent=styles['Heading2'],
        fontSize=13, textColor=PRIMARY, spaceBefore=16, spaceAfter=8,
        fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle('SubSection', parent=styles['Heading3'],
        fontSize=10, textColor=HexColor('#4a5568'), spaceBefore=10, spaceAfter=4,
        fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle('Body', parent=styles['Normal'],
        fontSize=9, leading=13, textColor=TEXT_DARK))
    styles.add(ParagraphStyle('BodySmall', parent=styles['Normal'],
        fontSize=8, leading=11, textColor=TEXT_MUTED))
    styles.add(ParagraphStyle('Mono', parent=styles['Normal'],
        fontSize=7.5, fontName='Courier', textColor=HexColor('#4a5568'),
        leading=10, backColor=LIGHT_BG))
    styles.add(ParagraphStyle('Centered', parent=styles['Normal'],
        fontSize=9, alignment=TA_CENTER, textColor=TEXT_DARK))
    styles.add(ParagraphStyle('Footer', parent=styles['Normal'],
        fontSize=7, textColor=TEXT_MUTED, alignment=TA_CENTER))

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
    color = level_colors.get(level, TEXT_MUTED)

    # ════════════════════════════════════════
    # COVER / HEADER BANNER
    # ════════════════════════════════════════
    banner_data = [['']]
    banner = Table(banner_data, colWidths=[174*mm], rowHeights=[42*mm])
    banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PRIMARY),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(banner)

    # Overlay title via paragraphs after banner
    story.append(Spacer(1, -38*mm))
    story.append(Paragraph("RAPPORT D'INCIDENT PHISHING", styles['CoverTitle']))
    story.append(Paragraph(f"SOC Analysis Report &mdash; {now}", styles['CoverSub']))
    story.append(Spacer(1, 8*mm))

    # ── Severity badge ──
    sev_text = f'SEVERITE: {level} &mdash; SCORE: {score}/100'
    sev_cell = [[Paragraph(f'<font color="#ffffff" size="14"><b>{sev_text}</b></font>',
                            ParagraphStyle('sev', alignment=TA_CENTER))]]
    sev_table = Table(sev_cell, colWidths=[174*mm], rowHeights=[12*mm])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(sev_table)

    if verdict.get("summary"):
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph(f'<i><font color="#718096">{_safe(verdict["summary"])}</font></i>',
                               styles['Centered']))
    story.append(Spacer(1, 4*mm))

    # ════════════════════════════════════════
    # 1. RESUME DE L'INCIDENT
    # ════════════════════════════════════════
    story.append(_section_header("1", "RESUME DE L'INCIDENT", PRIMARY))
    incident_data = [
        [_label_cell("Date du rapport"), now],
        [_label_cell("Sujet"), _safe(meta.get("subject", "N/A"))],
        [_label_cell("Expediteur"), _safe(meta.get("from", "N/A"))],
        [_label_cell("Destinataire(s)"), _safe(meta.get("to", "N/A"))],
        [_label_cell("Date de reception"), _safe(meta.get("date", "N/A"))],
        [_label_cell("Message-ID"), _safe(meta.get("message_id", "N/A"))],
        [_label_cell("Score de risque"), f"{score}/100 ({level})"],
    ]
    t = Table(incident_data, colWidths=[42*mm, 132*mm])
    t.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), PRIMARY),
        ('TEXTCOLOR', (1, 0), (1, -1), TEXT_DARK),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
        ('BACKGROUND', (0, 0), (0, -1), LIGHT_BG),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # ════════════════════════════════════════
    # 2. AUTHENTIFICATION
    # ════════════════════════════════════════
    story.append(_section_header("2", "VERIFICATION D'AUTHENTIFICATION", PRIMARY))
    auth_data = [["PROTOCOLE", "STATUT", "DETAILS"]]
    for proto in ['spf', 'dkim', 'dmarc']:
        item = auth.get(proto, {})
        status = item.get("status", "absent").upper()
        details = _safe(item.get("details", ""))[:80]
        auth_data.append([proto.upper(), status, details])

    t = Table(auth_data, colWidths=[28*mm, 24*mm, 122*mm])
    header_style = [
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), LIGHT_BG]),
    ]
    t.setStyle(TableStyle(header_style))
    # Color-code status
    for i, proto in enumerate(['spf', 'dkim', 'dmarc'], 1):
        status = auth.get(proto, {}).get("status", "absent")
        if status == "pass":
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), SUCCESS)]))
        elif status in ("fail", "softfail"):
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), DANGER)]))
        else:
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), WARNING)]))
    story.append(t)

    # ════════════════════════════════════════
    # 3. IOCs
    # ════════════════════════════════════════
    story.append(_section_header("3", "INDICATEURS DE COMPROMISSION (IOCs)", PRIMARY))

    # Stats bar
    url_count = iocs.get("urls_count", 0)
    suspicious_count = iocs.get("suspicious_urls_count", 0)
    ip_count = iocs.get("ips_count", 0)
    kw_count = iocs.get("keywords_count", 0)
    att_count = len(atts)

    stats_data = [[
        f"URLs: {url_count}", f"Suspectes: {suspicious_count}",
        f"IPs: {ip_count}", f"Mots-cles: {kw_count}", f"PJ: {att_count}"
    ]]
    st = Table(stats_data, colWidths=[35*mm]*5)
    st.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#edf2f7')),
        ('TEXTCOLOR', (0, 0), (-1, -1), PRIMARY),
        ('BOX', (0, 0), (-1, -1), 0.4, BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.4, BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(st)
    story.append(Spacer(1, 2*mm))

    urls = iocs.get("urls", [])
    if urls:
        story.append(Paragraph("<b>3.1 URLs detectees</b>", styles['SubSection']))
        url_data = [["URL", "DOMAINE", "FLAGS"]]
        for u in urls[:15]:
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("Shortener")
            if u.get("mismatched_display"): flags.append("Lien masque")
            url_data.append([
                _safe(u.get("url", ""))[:60],
                _safe(u.get("domain", "")),
                ", ".join(flags) or "—"
            ])
        t = _styled_table(url_data, [90*mm, 40*mm, 44*mm], PRIMARY)
        story.append(t)

    ips = iocs.get("ips", [])
    if ips:
        story.append(Paragraph("<b>3.2 Adresses IP</b>", styles['SubSection']))
        for ip_info in ips[:10]:
            priv = "Privee" if ip_info.get('is_private') else "Publique"
            story.append(Paragraph(
                f'&bull; <font face="Courier" size="8">{ip_info.get("ip", "N/A")}</font> ({priv})',
                styles['Body']))

    kws = iocs.get("phishing_keywords", [])
    if kws:
        story.append(Paragraph("<b>3.3 Mots-cles phishing detectes</b>", styles['SubSection']))
        story.append(Paragraph(", ".join(kws), styles['Body']))

    # ════════════════════════════════════════
    # 4. PIECES JOINTES
    # ════════════════════════════════════════
    if atts:
        story.append(_section_header("4", "PIECES JOINTES", PRIMARY))
        att_data = [["FICHIER", "TYPE", "TAILLE", "SUSPECT", "MD5"]]
        for att in atts:
            sus = "OUI" if att.get("suspicious_extension") else "Non"
            att_data.append([
                _safe(att.get("filename", ""))[:30],
                _safe(att.get("content_type", ""))[:25],
                _format_bytes(att.get("size_bytes", 0)),
                sus,
                att.get("md5", "")[:16] + "..."
            ])
        t = _styled_table(att_data, [42*mm, 35*mm, 18*mm, 16*mm, 63*mm], PRIMARY)
        # Highlight suspicious
        for i, att in enumerate(atts, 1):
            if att.get("suspicious_extension"):
                t.setStyle(TableStyle([
                    ('TEXTCOLOR', (3, i), (3, i), DANGER),
                    ('FONTNAME', (3, i), (3, i), 'Helvetica-Bold'),
                ]))
        story.append(t)

    # ════════════════════════════════════════
    # 5. FACTEURS DE RISQUE
    # ════════════════════════════════════════
    factors = risk.get("factors", [])
    if factors:
        story.append(_section_header("5", "FACTEURS DE RISQUE", PRIMARY))
        for f in factors:
            story.append(Paragraph(f'&bull; {_safe(f)}', styles['Body']))

    # ════════════════════════════════════════
    # 6. ANOMALIES
    # ════════════════════════════════════════
    anomalies = headers_a.get("anomalies", [])
    if anomalies:
        story.append(_section_header("6", "ANOMALIES DE HEADERS", PRIMARY))
        for a in anomalies:
            story.append(Paragraph(f'&bull; {_safe(a)}', styles['Body']))

    # ════════════════════════════════════════
    # 7. ANALYSE IA
    # ════════════════════════════════════════
    if ai and not ai.get("error"):
        story.append(PageBreak())
        story.append(_section_header("7", "ANALYSE IA — SOCIAL ENGINEERING", ACCENT))

        sem = ai.get("semantic_analysis", {})
        imp = ai.get("impersonation", {})
        soph = ai.get("sophistication", {})

        ai_data = [
            [_label_cell("Emotion ciblee"), _safe(sem.get("target_emotion", "N/A"))],
            [_label_cell("Pretexte"), _safe(sem.get("pretext", imp.get("pretext", "N/A")))],
            [_label_cell("Entite usurpee"), _safe(imp.get("impersonated_entity", "N/A"))],
            [_label_cell("Qualite usurpation"), f"{imp.get('impersonation_quality', 'N/A')}/10"],
            [_label_cell("Credibilite"), f"{sem.get('credibility_assessment', 'N/A')}/10"],
            [_label_cell("Sophistication"), f"{soph.get('level', 'N/A')} ({soph.get('score', 'N/A')}/10)"],
            [_label_cell("Confiance IA"), f"{round((ai.get('ai_confidence', 0)) * 100)}%"],
        ]
        t = Table(ai_data, colWidths=[42*mm, 132*mm])
        t.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (0, -1), ACCENT),
            ('GRID', (0, 0), (-1, -1), 0.4, BORDER),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#fff5f5')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

        # Tactics
        tactics = ai.get("social_engineering_tactics", [])
        if tactics:
            story.append(Paragraph("<b>7.1 Tactiques de manipulation</b>", styles['SubSection']))
            tac_data = [["TACTIQUE", "PRINCIPE CIALDINI", "EFFICACITE"]]
            for tac in tactics:
                tac_data.append([
                    _safe(tac.get("tactic", "")),
                    _safe(tac.get("cialdini_principle", "")),
                    _safe(tac.get("effectiveness", "")).upper()
                ])
            t = _styled_table(tac_data, [55*mm, 65*mm, 54*mm], ACCENT)
            story.append(t)

        # MITRE
        mitre = ai.get("mitre_techniques", [])
        if mitre:
            story.append(Paragraph("<b>7.2 Mapping MITRE ATT&amp;CK</b>", styles['SubSection']))
            mitre_data = [["ID", "TECHNIQUE", "PERTINENCE"]]
            for m in mitre:
                mitre_data.append([m.get("id", ""), _safe(m.get("name", "")), _safe(m.get("relevance", ""))[:60]])
            t = _styled_table(mitre_data, [25*mm, 60*mm, 89*mm], ACCENT)
            story.append(t)

        if ai.get("executive_summary"):
            story.append(Paragraph("<b>7.3 Resume executif</b>", styles['SubSection']))
            # Box around executive summary
            sum_data = [[Paragraph(_safe(ai["executive_summary"]), styles['Body'])]]
            sum_t = Table(sum_data, colWidths=[170*mm])
            sum_t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), HexColor('#fefcbf')),
                ('BOX', (0, 0), (-1, -1), 0.6, WARNING),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ]))
            story.append(sum_t)

    # ════════════════════════════════════════
    # 8. RECOMMANDATIONS
    # ════════════════════════════════════════
    recs = ai.get("recommended_actions", []) if ai else []
    rec_from_verdict = verdict.get("recommendation", "")
    if recs or rec_from_verdict:
        story.append(_section_header("8", "ACTIONS RECOMMANDEES", PRIMARY))
        rec_content = []
        if recs:
            for i, r in enumerate(recs, 1):
                rec_content.append(Paragraph(
                    f'<font color="{PRIMARY.hexval()}" face="Helvetica-Bold">{i}.</font> {_safe(r)}',
                    styles['Body']))
                rec_content.append(Spacer(1, 1*mm))
        elif rec_from_verdict:
            for line in rec_from_verdict.split("\n"):
                if line.strip():
                    rec_content.append(Paragraph(_safe(line.strip()), styles['Body']))

        rec_box = [[rec_content]]
        # Can't directly put list in table; flatten
        rec_inner = []
        if recs:
            for i, r in enumerate(recs, 1):
                rec_inner.append(Paragraph(
                    f'<font color="{PRIMARY.hexval()}" face="Helvetica-Bold">{i}.</font> {_safe(r)}',
                    styles['Body']))
        elif rec_from_verdict:
            for line in rec_from_verdict.split("\n"):
                if line.strip():
                    rec_inner.append(Paragraph(_safe(line.strip()), styles['Body']))
        for p in rec_inner:
            story.append(p)
            story.append(Spacer(1, 1*mm))

    # ════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f'Rapport genere par <b>Phishing Email Forensics</b> &mdash; {now} &mdash; CONFIDENTIEL',
        styles['Footer']))

    doc.build(story)
    return buf.getvalue()


def generate_docx_report(analysis: dict) -> bytes:
    """Génère un rapport DOCX d'incident SOC professionnel."""
    from docx import Document
    from docx.shared import Inches, Pt, Cm, RGBColor, Emu
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn, nsdecls
    from docx.oxml import parse_xml

    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin = Cm(1.5)
        section.bottom_margin = Cm(1.5)
        section.left_margin = Cm(2)
        section.right_margin = Cm(2)

    # Color constants
    PRIMARY = RGBColor(0x0f, 0x34, 0x60)
    ACCENT = RGBColor(0xe9, 0x45, 0x60)
    TEXT_DARK = RGBColor(0x2d, 0x37, 0x48)
    TEXT_MUTED = RGBColor(0x71, 0x80, 0x96)
    WHITE = RGBColor(0xff, 0xff, 0xff)

    level_colors = {
        'CRITICAL': RGBColor(0xe7, 0x4c, 0x3c), 'HIGH': RGBColor(0xe6, 0x7e, 0x22),
        'MEDIUM': RGBColor(0x34, 0x98, 0xdb), 'LOW': RGBColor(0x27, 0xae, 0x60),
        'INFO': RGBColor(0x95, 0xa5, 0xa6)
    }

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
    level_color = level_colors.get(level, TEXT_MUTED)

    # ── Helper: colored shading ──
    def _set_cell_bg(cell, color_hex):
        shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
        cell._tc.get_or_add_tcPr().append(shading)

    def _add_section_heading(text, num=None):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(6)
        if num:
            run = p.add_run(f"{num}. ")
            run.font.size = Pt(14)
            run.font.color.rgb = PRIMARY
            run.bold = True
        run = p.add_run(text)
        run.font.size = Pt(14)
        run.font.color.rgb = PRIMARY
        run.bold = True
        # Add underline bar
        border_p = doc.add_paragraph()
        border_p.paragraph_format.space_before = Pt(0)
        border_p.paragraph_format.space_after = Pt(6)
        pPr = border_p._p.get_or_add_pPr()
        pBdr = parse_xml(
            f'<w:pBdr {nsdecls("w")}>'
            f'  <w:bottom w:val="single" w:sz="6" w:space="1" w:color="0F3460"/>'
            f'</w:pBdr>'
        )
        pPr.append(pBdr)

    def _styled_table(data, style_name='Table Grid'):
        """Create a table with professional styling."""
        table = doc.add_table(rows=len(data), cols=len(data[0]))
        table.style = style_name
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, row in enumerate(data):
            for j, val in enumerate(row):
                cell = table.rows[i].cells[j]
                cell.text = str(val or "")
                for p in cell.paragraphs:
                    p.paragraph_format.space_after = Pt(2)
                    p.paragraph_format.space_before = Pt(2)
                    for r in p.runs:
                        r.font.size = Pt(9)
                        r.font.color.rgb = TEXT_DARK
                if i == 0:
                    _set_cell_bg(cell, "0F3460")
                    for p in cell.paragraphs:
                        for r in p.runs:
                            r.font.color.rgb = WHITE
                            r.bold = True
                            r.font.size = Pt(9)
                elif i % 2 == 0:
                    _set_cell_bg(cell, "F8F9FC")
        return table

    # ════════════════════════════════════════
    # COVER / TITLE
    # ════════════════════════════════════════
    # Title banner using a 1-cell table with colored background
    banner = doc.add_table(rows=1, cols=1)
    banner.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = banner.rows[0].cells[0]
    _set_cell_bg(cell, "0F3460")
    cell.height = Cm(3.5)

    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(20)
    run = p.add_run("RAPPORT D'INCIDENT PHISHING")
    run.font.size = Pt(24)
    run.font.color.rgb = WHITE
    run.bold = True

    p2 = cell.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run2 = p2.add_run(f"SOC Analysis Report — {now}")
    run2.font.size = Pt(11)
    run2.font.color.rgb = RGBColor(0xcb, 0xd5, 0xe0)

    doc.add_paragraph()  # spacer

    # Severity banner
    sev_table = doc.add_table(rows=1, cols=1)
    sev_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    sev_cell = sev_table.rows[0].cells[0]
    color_hex = f"{level_color.red:02x}{level_color.green:02x}{level_color.blue:02x}"
    _set_cell_bg(sev_cell, color_hex)
    p = sev_cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"SEVERITE: {level} — SCORE: {score}/100")
    run.font.size = Pt(14)
    run.font.color.rgb = WHITE
    run.bold = True

    if verdict.get("summary"):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(verdict["summary"])
        run.italic = True
        run.font.size = Pt(10)
        run.font.color.rgb = TEXT_MUTED

    # ════════════════════════════════════════
    # 1. RESUME
    # ════════════════════════════════════════
    _add_section_heading("RESUME DE L'INCIDENT", "1")
    rows_data = [
        ["Champ", "Valeur"],
        ["Date du rapport", now],
        ["Sujet", meta.get("subject", "N/A")],
        ["Expediteur", meta.get("from", "N/A")],
        ["Destinataire(s)", meta.get("to", "N/A")],
        ["Date reception", meta.get("date", "N/A")],
        ["Message-ID", meta.get("message_id", "N/A")],
        ["Score de risque", f"{score}/100 ({level})"],
    ]
    _styled_table(rows_data)

    # ════════════════════════════════════════
    # 2. AUTHENTIFICATION
    # ════════════════════════════════════════
    _add_section_heading("VERIFICATION D'AUTHENTIFICATION", "2")
    auth_rows = [["Protocole", "Statut", "Details"]]
    for proto in ['spf', 'dkim', 'dmarc']:
        item = auth.get(proto, {})
        auth_rows.append([
            proto.upper(),
            item.get("status", "absent").upper(),
            (item.get("details", "") or "")[:70]
        ])
    table = _styled_table(auth_rows)
    # Color-code status cells
    for i, proto in enumerate(['spf', 'dkim', 'dmarc'], 1):
        status = auth.get(proto, {}).get("status", "absent")
        cell = table.rows[i].cells[1]
        for p in cell.paragraphs:
            for r in p.runs:
                if status == "pass":
                    r.font.color.rgb = RGBColor(0x27, 0xae, 0x60)
                elif status in ("fail", "softfail"):
                    r.font.color.rgb = RGBColor(0xe7, 0x4c, 0x3c)
                else:
                    r.font.color.rgb = RGBColor(0xf3, 0x9c, 0x12)
                r.bold = True

    # ════════════════════════════════════════
    # 3. IOCs
    # ════════════════════════════════════════
    _add_section_heading("INDICATEURS DE COMPROMISSION (IOCs)", "3")

    urls = iocs.get("urls", [])
    if urls:
        doc.add_heading("3.1 URLs detectees", level=2)
        url_rows = [["URL", "Flags"]]
        for u in urls[:15]:
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("Shortener")
            if u.get("mismatched_display"): flags.append("Lien masque")
            url_rows.append([(u.get("url", ""))[:65], ", ".join(flags) or "—"])
        _styled_table(url_rows)

    kws = iocs.get("phishing_keywords", [])
    if kws:
        doc.add_heading("3.2 Mots-cles phishing", level=2)
        doc.add_paragraph(", ".join(kws))

    # ════════════════════════════════════════
    # 4. PIECES JOINTES
    # ════════════════════════════════════════
    if atts:
        _add_section_heading("PIECES JOINTES", "4")
        att_rows = [["Fichier", "Type", "Taille", "Suspect", "MD5"]]
        for att in atts:
            att_rows.append([
                att.get("filename", ""),
                att.get("content_type", ""),
                _format_bytes(att.get("size_bytes", 0)),
                "OUI" if att.get("suspicious_extension") else "Non",
                att.get("md5", "")[:20] + "..."
            ])
        table = _styled_table(att_rows)
        # Highlight suspicious
        for i, att in enumerate(atts, 1):
            if att.get("suspicious_extension"):
                cell = table.rows[i].cells[3]
                for p in cell.paragraphs:
                    for r in p.runs:
                        r.font.color.rgb = RGBColor(0xe7, 0x4c, 0x3c)
                        r.bold = True

    # ════════════════════════════════════════
    # 5. FACTEURS DE RISQUE
    # ════════════════════════════════════════
    factors = risk.get("factors", [])
    if factors:
        _add_section_heading("FACTEURS DE RISQUE", "5")
        for f in factors:
            doc.add_paragraph(f, style='List Bullet')

    # ════════════════════════════════════════
    # 6. ANOMALIES
    # ════════════════════════════════════════
    anomalies = headers_a.get("anomalies", [])
    if anomalies:
        _add_section_heading("ANOMALIES DE HEADERS", "6")
        for a in anomalies:
            doc.add_paragraph(a, style='List Bullet')

    # ════════════════════════════════════════
    # 7. ANALYSE IA
    # ════════════════════════════════════════
    if ai and not ai.get("error"):
        doc.add_page_break()
        _add_section_heading("ANALYSE IA — SOCIAL ENGINEERING", "7")

        sem = ai.get("semantic_analysis", {})
        imp = ai.get("impersonation", {})
        soph = ai.get("sophistication", {})

        ai_rows = [
            ["Champ", "Valeur"],
            ["Emotion ciblee", sem.get("target_emotion", "N/A")],
            ["Pretexte", sem.get("pretext", imp.get("pretext", "N/A"))],
            ["Entite usurpee", imp.get("impersonated_entity", "N/A")],
            ["Sophistication", f"{soph.get('level', 'N/A')} ({soph.get('score', 'N/A')}/10)"],
            ["Confiance IA", f"{round(ai.get('ai_confidence', 0) * 100)}%"],
        ]
        _styled_table(ai_rows)

        tactics = ai.get("social_engineering_tactics", [])
        if tactics:
            doc.add_heading("7.1 Tactiques de manipulation", level=2)
            tac_rows = [["Tactique", "Principe Cialdini", "Efficacite"]]
            for tac in tactics:
                tac_rows.append([
                    tac.get("tactic", ""),
                    tac.get("cialdini_principle", ""),
                    (tac.get("effectiveness", "")).upper()
                ])
            _styled_table(tac_rows)

        mitre = ai.get("mitre_techniques", [])
        if mitre:
            doc.add_heading("7.2 Mapping MITRE ATT&CK", level=2)
            mitre_rows = [["ID", "Technique", "Pertinence"]]
            for m in mitre:
                mitre_rows.append([m.get("id", ""), m.get("name", ""), m.get("relevance", "")[:60]])
            _styled_table(mitre_rows)

        if ai.get("executive_summary"):
            doc.add_heading("7.3 Resume executif", level=2)
            p = doc.add_paragraph()
            run = p.add_run(ai["executive_summary"])
            run.font.size = Pt(10)
            run.font.color.rgb = TEXT_DARK

    # ════════════════════════════════════════
    # 8. RECOMMANDATIONS
    # ════════════════════════════════════════
    recs = ai.get("recommended_actions", []) if ai else []
    rec_from_verdict = verdict.get("recommendation", "")
    if recs or rec_from_verdict:
        _add_section_heading("ACTIONS RECOMMANDEES", "8")
        if recs:
            for i, r in enumerate(recs, 1):
                p = doc.add_paragraph()
                run_num = p.add_run(f"{i}. ")
                run_num.bold = True
                run_num.font.color.rgb = PRIMARY
                run_text = p.add_run(r)
                run_text.font.size = Pt(10)
        elif rec_from_verdict:
            for line in rec_from_verdict.split("\n"):
                if line.strip():
                    doc.add_paragraph(line.strip())

    # ════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════
    doc.add_paragraph()
    footer = doc.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run(f"Rapport genere par Phishing Email Forensics — {now} — CONFIDENTIEL")
    run.font.size = Pt(8)
    run.font.color.rgb = TEXT_MUTED

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ════════════════════════════════════════
# PDF Helpers
# ════════════════════════════════════════

def _section_header(num, title, color):
    """Creates a styled section header for PDF."""
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import Table, TableStyle, Paragraph
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT

    style = ParagraphStyle('sh', fontSize=12, fontName='Helvetica-Bold',
                           textColor=color, leading=16)
    content = Paragraph(f"{num}. {title}", style)
    data = [[content]]
    t = Table(data, colWidths=[174*mm], rowHeights=[10*mm])
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LINEBELOW', (0, 0), (-1, -1), 1.5, color),
    ]))
    return t


def _styled_table(data, col_widths, header_color):
    """Creates a professionally styled table for PDF."""
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import Table, TableStyle

    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 0), (-1, 0), header_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 0.3, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#f8f9fc')]),
    ]))
    return t


def _label_cell(text):
    """Returns text for a label column."""
    return text


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
