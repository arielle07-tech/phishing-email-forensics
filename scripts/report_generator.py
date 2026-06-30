#!/usr/bin/env python3
"""
Phishing Email Forensics — Report Generator
=============================================
Génère des rapports d'incident SOC en PDF et DOCX.

Structure alignée sur le framework SOC (clevertailor) :
 1. Executive Summary — what happened, impact, key takeaway
 2. Alert Details — source, time, severity, description
 3. Triage Decision — true/false positive and why
 4. Enrichment Findings — IP/Domain reputation, context, evidence
 5. MITRE ATT&CK Mapping — tactic, technique, ID, description
 6. Recommended Response — next steps and ownership
 A. Annexes techniques (headers bruts, analyse IA détaillée)
"""

import io
import os
import re
import hashlib
from datetime import datetime


# ════════════════════════════════════════
# Utility functions
# ════════════════════════════════════════

def _safe(text: str) -> str:
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


def _defang_url(url: str) -> str:
    if not url:
        return ""
    url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    url = url.replace("://", "[://]")
    parts = url.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        return "/".join(parts)
    return url.replace(".", "[.]")


def _defang_ip(ip: str) -> str:
    if not ip:
        return ""
    return ip.replace(".", "[.]")


def _defang_domain(domain: str) -> str:
    if not domain:
        return ""
    return domain.replace(".", "[.]")


def _generate_incident_id(analysis: dict) -> str:
    meta = analysis.get("metadata", {})
    seed = f"{meta.get('message_id', '')}{meta.get('date', '')}{meta.get('from', '')}"
    h = hashlib.md5(seed.encode()).hexdigest()[:6].upper()
    return f"INC-{datetime.now().strftime('%Y')}-{h}"


def _generate_report_number(analysis: dict) -> str:
    """Génère un numéro de rapport unique pour suivi (RPT-YYYYMMDD-XXXXXX)."""
    meta = analysis.get("metadata", {})
    seed = f"{meta.get('message_id', '')}{datetime.now().isoformat()}{meta.get('from', '')}"
    h = hashlib.md5(seed.encode()).hexdigest()[:6].upper()
    return f"RPT-{datetime.now().strftime('%Y%m%d')}-{h}"


def _clean_recommendation(text: str) -> str:
    """Supprime la numérotation en début de recommandation (ex: '1. ', '2. ')."""
    import re
    return re.sub(r'^\d+[\.\)\-]\s*', '', text.strip())


def _classify_incident(analysis: dict) -> dict:
    ai = analysis.get("ai_analysis", {})
    iocs = analysis.get("iocs", {})
    atts = analysis.get("attachments", [])
    verdict = analysis.get("verdict", {})
    score = verdict.get("score", 0)

    has_malicious_att = any(a.get("suspicious_extension") for a in atts)
    has_credential_keywords = any(
        kw in (iocs.get("phishing_keywords", []))
        for kw in ["verify your account", "password expired", "reset your password",
                    "confirm your identity", "vérifiez votre compte", "mot de passe expiré"]
    )
    imp_entity = ai.get("impersonation", {}).get("impersonated_entity", "")

    if has_malicious_att:
        category = "Malware Delivery"
        sub_category = "Phishing avec pièce jointe malveillante"
    elif has_credential_keywords:
        category = "Credential Harvesting"
        sub_category = "Vol d'identifiants via formulaire frauduleux"
    elif imp_entity and imp_entity != "N/A":
        category = "Business Email Compromise (BEC)"
        sub_category = f"Usurpation d'identité — {imp_entity}"
    else:
        category = "Phishing générique"
        sub_category = "Tentative de phishing non catégorisée"

    level = verdict.get("risk_level", "INFO")
    severity_map = {
        "CRITICAL": ("P1", "Critique — Réponse immédiate requise"),
        "HIGH": ("P2", "Élevée — Traitement prioritaire"),
        "MEDIUM": ("P3", "Modérée — Traitement dans les 24h"),
        "LOW": ("P4", "Faible — Surveillance recommandée"),
        "INFO": ("P5", "Informationnel — Aucune action requise"),
    }
    priority, severity_desc = severity_map.get(level, ("P5", "Non classifié"))

    return {
        "category": category,
        "sub_category": sub_category,
        "priority": priority,
        "severity_description": severity_desc,
        "tlp": "TLP:AMBER" if score >= 45 else "TLP:GREEN",
        "mitre_tactics": [m.get("id", "") for m in ai.get("mitre_techniques", [])],
    }


def _build_executive_summary(analysis: dict, classification: dict, incident_id: str) -> str:
    """Construit un résumé exécutif one-liner + contexte, même sans IA."""
    verdict = analysis.get("verdict", {})
    meta = analysis.get("metadata", {})
    ai = analysis.get("ai_analysis", {})
    score = verdict.get("score", 0)
    level = verdict.get("risk_level", "INFO")

    # Use AI executive summary if available
    ai_summary = ""
    if ai and not ai.get("error"):
        ai_summary = ai.get("executive_summary", "")

    # Build the one-liner (always present)
    sender = meta.get("from", "Inconnu")
    subject = meta.get("subject", "Sans objet")
    one_liner = (
        f"Severity: {level} — {classification['category']} "
        f"detecte depuis {_safe(sender)} "
        f"(score {score}/100)."
    )

    if ai_summary:
        return f"{one_liner}\n\n{ai_summary}"
    else:
        verdict_summary = verdict.get("summary", "")
        if verdict_summary:
            return f"{one_liner}\n\n{verdict_summary}"
        return one_liner


def _build_timeline(analysis: dict) -> list:
    meta = analysis.get("metadata", {})
    timeline = []
    email_date = meta.get("date", "")
    analysis_ts = meta.get("analysis_timestamp", "")
    now = datetime.now().strftime("%d/%m/%Y %H:%M UTC")

    if email_date:
        timeline.append(("Reception", email_date, "Email suspect recu par le destinataire"))
    timeline.append(("Soumission", analysis_ts or now, "Email soumis a la plateforme d'analyse"))
    timeline.append(("Analyse", now, "Extraction IOCs, authentification, scoring"))
    ai = analysis.get("ai_analysis", {})
    if ai and not ai.get("error"):
        timeline.append(("Analyse IA", now, "Tactiques social engineering identifiees"))
    timeline.append(("Rapport", now, "Rapport genere, pret pour escalade"))
    return timeline


# ════════════════════════════════════════════════════════════════
#
#   PDF REPORT
#
# ════════════════════════════════════════════════════════════════

def generate_pdf_report(analysis: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import mm
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            topMargin=15*mm, bottomMargin=18*mm,
                            leftMargin=18*mm, rightMargin=18*mm)
    styles = getSampleStyleSheet()

    # Colors
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

    # Styles
    styles.add(ParagraphStyle('CoverTitle', parent=styles['Title'],
        fontSize=26, textColor=HexColor('#ffffff'), alignment=TA_CENTER,
        spaceAfter=4, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle('CoverSub', parent=styles['Normal'],
        fontSize=12, textColor=HexColor('#cbd5e0'), alignment=TA_CENTER,
        spaceAfter=2))
    styles.add(ParagraphStyle('Body', parent=styles['Normal'],
        fontSize=9, leading=13, textColor=TEXT_DARK))
    styles.add(ParagraphStyle('BodySmall', parent=styles['Normal'],
        fontSize=8, leading=11, textColor=TEXT_MUTED))
    styles.add(ParagraphStyle('SubSection', parent=styles['Heading3'],
        fontSize=10, textColor=HexColor('#4a5568'), spaceBefore=10, spaceAfter=4,
        fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle('Mono', parent=styles['Normal'],
        fontSize=7, fontName='Courier', textColor=HexColor('#4a5568'),
        leading=9, backColor=LIGHT_BG))
    styles.add(ParagraphStyle('Centered', parent=styles['Normal'],
        fontSize=9, alignment=TA_CENTER, textColor=TEXT_DARK))
    styles.add(ParagraphStyle('Footer', parent=styles['Normal'],
        fontSize=7, textColor=TEXT_MUTED, alignment=TA_CENTER))

    story = []

    # Extract data
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
    incident_id = _generate_incident_id(analysis)
    report_number = _generate_report_number(analysis)
    classification = _classify_incident(analysis)
    timeline = _build_timeline(analysis)
    exec_summary = _build_executive_summary(analysis, classification, incident_id)
    sec = 0  # dynamic section counter

    # ════════════════════════════════════════
    # HEADER BANNER
    # ════════════════════════════════════════
    banner = Table([['']], colWidths=[174*mm], rowHeights=[48*mm])
    banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PRIMARY),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(banner)
    story.append(Spacer(1, -44*mm))
    story.append(Paragraph("RAPPORT D'INCIDENT PHISHING", styles['CoverTitle']))
    story.append(Paragraph(f"Rapport N° {report_number}", styles['CoverSub']))
    story.append(Paragraph(f"Incident {incident_id} &mdash; {now} &mdash; {classification['tlp']}", styles['CoverSub']))
    story.append(Spacer(1, 8*mm))

    # Severity badge
    sev_text = f"SEVERITE: {level} &mdash; {classification['priority']} &mdash; SCORE: {score}/100"
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
    story.append(Spacer(1, 4*mm))

    # ════════════════════════════════════════
    # SOMMAIRE (table of contents)
    # ════════════════════════════════════════
    # Build section list dynamically
    has_mitre = bool((ai.get("mitre_techniques", []) if ai else []) or
                     (ai.get("social_engineering_tactics", []) if ai else []) or
                     classification.get("mitre_tactics"))
    toc_items = [
        "Executive Summary",
        "Alert Details",
        "Triage Decision",
        "Enrichment Findings",
    ]
    if has_mitre:
        toc_items.append("MITRE ATT&CK Mapping")
    toc_items.append("Recommended Response")

    toc_text = " &mdash; ".join([f"<b>{i+1}.</b> {t}" for i, t in enumerate(toc_items)])
    toc_text += " &mdash; <b>A/B.</b> Annexes"
    story.append(Paragraph(toc_text, styles['BodySmall']))
    story.append(Spacer(1, 4*mm))

    # ════════════════════════════════════════
    # §1. EXECUTIVE SUMMARY
    # ════════════════════════════════════════
    sec += 1
    story.append(_pdf_section_header(str(sec), "EXECUTIVE SUMMARY", PRIMARY))

    # One-liner box (highlighted)
    one_liner = (
        f"Severity: {level} &mdash; {_safe(classification['category'])} "
        f"detecte depuis {_safe(meta.get('from', 'Inconnu'))} "
        f"(score {score}/100)."
    )
    one_box = [[Paragraph(f'<b>{one_liner}</b>', styles['Body'])]]
    one_t = Table(one_box, colWidths=[174*mm])
    one_t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#fefcbf')),
        ('BOX', (0, 0), (-1, -1), 0.8, WARNING),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(one_t)
    story.append(Spacer(1, 2*mm))

    # Full summary (AI or verdict)
    ai_summary = ""
    if ai and not ai.get("error"):
        ai_summary = ai.get("executive_summary", "")
    if ai_summary:
        story.append(Paragraph(_safe(ai_summary), styles['Body']))
    elif verdict.get("summary"):
        story.append(Paragraph(_safe(verdict["summary"]), styles['Body']))

    # Key takeaway: impact + classification
    story.append(Spacer(1, 2*mm))
    impact_text = (
        f"<b>Impact :</b> {classification['sub_category']}. "
        f"<b>Priorite :</b> {classification['priority']} &mdash; {classification['severity_description']}. "
        f"<b>TLP :</b> {classification['tlp']}."
    )
    story.append(Paragraph(impact_text, styles['Body']))

    # ════════════════════════════════════════
    # §2. ALERT DETAILS
    # ════════════════════════════════════════
    sec += 1
    story.append(_pdf_section_header(str(sec), "ALERT DETAILS", PRIMARY))
    alert_data = [
        ["N° Rapport", report_number],
        ["N° Incident", incident_id],
        ["Date du rapport", now],
        ["Sujet", _safe(meta.get("subject", "N/A"))],
        ["Expediteur", _safe(meta.get("from", "N/A"))],
        ["Destinataire(s)", _safe(meta.get("to", "N/A"))],
        ["Date de reception", _safe(meta.get("date", "N/A"))],
        ["Message-ID", _safe(meta.get("message_id", "N/A"))],
        ["Return-Path", _safe(meta.get("return_path", "N/A"))],
        ["Categorie", classification["category"]],
        ["Score", f"{score}/100 ({level})"],
    ]
    story.append(_pdf_info_table(alert_data, PRIMARY))

    # Timeline
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("<b>Chronologie</b>", styles['SubSection']))
    tl_data = [["PHASE", "HORODATAGE", "DESCRIPTION"]]
    for phase, ts, desc in timeline:
        tl_data.append([phase, _safe(ts)[:30], desc])
    story.append(_pdf_styled_table(tl_data, [32*mm, 42*mm, 100*mm], PRIMARY))

    # ════════════════════════════════════════
    # 3. TRIAGE DECISION
    # ════════════════════════════════════════
    sec += 1
    story.append(_pdf_section_header(str(sec), "TRIAGE DECISION", PRIMARY))

    # True/false positive assessment
    if score >= 45:
        triage_verdict = "TRUE POSITIVE"
        triage_reason = (
            f"L'analyse a identifie {classification['category'].lower()} avec un score de {score}/100. "
        )
        triage_color = DANGER
    elif score >= 25:
        triage_verdict = "SUSPICIOUS — INVESTIGATION REQUISE"
        triage_reason = (
            f"Elements suspects detectes (score {score}/100) mais insuffisants pour confirmer. "
            f"Investigation manuelle recommandee."
        )
        triage_color = WARNING
    else:
        triage_verdict = "PROBABLE FALSE POSITIVE"
        triage_reason = f"Score faible ({score}/100). Aucun indicateur de compromission significatif."
        triage_color = SUCCESS

    # Triage badge
    triage_cell = [[Paragraph(
        f'<font color="#ffffff" size="12"><b>{triage_verdict}</b></font>',
        ParagraphStyle('tv', alignment=TA_CENTER))]]
    triage_t = Table(triage_cell, colWidths=[174*mm], rowHeights=[10*mm])
    triage_t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), triage_color),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(triage_t)
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(_safe(triage_reason), styles['Body']))

    # Scoring breakdown
    factors = risk.get("factors", [])
    if factors:
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("<b>Facteurs de risque (scoring breakdown)</b>", styles['SubSection']))
        for f in factors:
            story.append(Paragraph(f'&bull; {_safe(f)}', styles['Body']))

    # Authentication summary
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("<b>Authentification email</b>", styles['SubSection']))
    auth_data = [["PROTOCOLE", "STATUT", "DETAILS"]]
    for proto in ['spf', 'dkim', 'dmarc']:
        item = auth.get(proto, {})
        status = item.get("status", "absent").upper()
        details = _safe(item.get("details", ""))[:80]
        auth_data.append([proto.upper(), status, details])
    t = _pdf_styled_table(auth_data, [28*mm, 24*mm, 122*mm], PRIMARY)
    for i, proto in enumerate(['spf', 'dkim', 'dmarc'], 1):
        status = auth.get(proto, {}).get("status", "absent")
        if status == "pass":
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), SUCCESS)]))
        elif status in ("fail", "softfail"):
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), DANGER)]))
        else:
            t.setStyle(TableStyle([('TEXTCOLOR', (1, i), (1, i), WARNING)]))
    story.append(t)

    # Anomalies
    anomalies = headers_a.get("anomalies", [])
    if anomalies:
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("<b>Anomalies detectees</b>", styles['SubSection']))
        for a in anomalies:
            story.append(Paragraph(f'&bull; {_safe(a)}', styles['Body']))

    # ════════════════════════════════════════
    # 4. ENRICHMENT FINDINGS
    # ════════════════════════════════════════
    story.append(PageBreak())
    sec += 1
    story.append(_pdf_section_header(str(sec), "ENRICHMENT FINDINGS", PRIMARY))

    story.append(Paragraph(
        '<i><font color="#718096">IOCs au format defange (hxxps, [.]) pour partage securise.</font></i>',
        styles['BodySmall']))
    story.append(Spacer(1, 2*mm))

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

    # 4.1 URLs
    urls = iocs.get("urls", [])
    if urls:
        story.append(Paragraph("<b>4.1 URLs detectees</b>", styles['SubSection']))
        url_data = [["URL (DEFANGED)", "DOMAINE", "FLAGS"]]
        for u in urls[:15]:
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("Shortener")
            if u.get("mismatched_display"): flags.append("Lien masque")
            url_data.append([
                _safe(_defang_url(u.get("url", "")))[:65],
                _safe(_defang_domain(u.get("domain", ""))),
                ", ".join(flags) or "—"
            ])
        story.append(_pdf_styled_table(url_data, [90*mm, 40*mm, 44*mm], PRIMARY))

    # 4.2 IPs with threat intel
    ips = iocs.get("ips", [])
    if ips:
        story.append(Paragraph("<b>4.2 Adresses IP</b>", styles['SubSection']))
        ip_data = [["IP (DEFANGED)", "TYPE", "THREAT INTEL"]]
        for ip_info in ips[:10]:
            priv = "Privee" if ip_info.get('is_private') else "Publique"
            ip_str = _defang_ip(ip_info.get("ip", ""))
            vt_ref = f"VT: rechercher {ip_str}"
            ip_data.append([ip_str, priv, vt_ref])
        story.append(_pdf_styled_table(ip_data, [40*mm, 24*mm, 110*mm], PRIMARY))

    # 4.3 Received chain (hop analysis)
    received_chain = headers_a.get("received_chain", [])
    if received_chain:
        story.append(Paragraph("<b>4.3 Chaine de transmission (Received hops)</b>", styles['SubSection']))
        story.append(Paragraph(
            f"L'email a traverse <b>{len(received_chain)}</b> serveur(s).",
            styles['Body']))
        story.append(Spacer(1, 1*mm))
        hop_data = [["HOP", "IP(s)", "DETAILS"]]
        for hop in received_chain:
            ips_str = ", ".join(_defang_ip(ip) for ip in hop.get("ips_found", [])) or "—"
            raw = _safe(hop.get("raw", ""))[:120]
            hop_data.append([str(hop.get("hop", "")), ips_str, raw])
        story.append(_pdf_styled_table(hop_data, [14*mm, 36*mm, 124*mm], PRIMARY))

    # 4.4 Phishing keywords
    kws = iocs.get("phishing_keywords", [])
    if kws:
        story.append(Paragraph("<b>4.4 Mots-cles phishing</b>", styles['SubSection']))
        story.append(Paragraph(", ".join(kws), styles['Body']))

    # 4.5 Attachments (full hashes)
    if atts:
        story.append(Paragraph("<b>4.5 Pieces jointes</b>", styles['SubSection']))
        for att in atts:
            sus_label = "SUSPECT" if att.get("suspicious_extension") else "Normal"
            sus_color = DANGER if att.get("suspicious_extension") else SUCCESS
            att_info = [
                ["Fichier", _safe(att.get("filename", ""))],
                ["Type MIME", _safe(att.get("content_type", ""))],
                ["Taille", _format_bytes(att.get("size_bytes", 0))],
                ["Statut", sus_label],
                ["MD5", att.get("md5", "N/A")],
                ["SHA256", att.get("sha256", "N/A")],
            ]
            story.append(_pdf_info_table(att_info, sus_color))
            sha256 = att.get("sha256", "")
            if sha256 and sha256 != "N/A":
                story.append(Paragraph(
                    f'<font face="Courier" size="7" color="#718096">'
                    f'VirusTotal: hxxps[://]www[.]virustotal[.]com/gui/file/{sha256}</font>',
                    styles['BodySmall']))
            story.append(Spacer(1, 2*mm))

    # ════════════════════════════════════════
    # 5. MITRE ATT&CK MAPPING
    # ════════════════════════════════════════
    mitre = ai.get("mitre_techniques", []) if ai else []
    tactics = ai.get("social_engineering_tactics", []) if ai else []
    if mitre or tactics or classification.get("mitre_tactics"):
        sec += 1
        story.append(_pdf_section_header(str(sec), "MITRE ATT&CK MAPPING", ACCENT))

        if mitre:
            mitre_data = [["ID", "TECHNIQUE", "TACTIC", "PERTINENCE"]]
            for m in mitre:
                mitre_data.append([
                    m.get("id", ""),
                    _safe(m.get("name", "")),
                    _safe(m.get("tactic", "Initial Access")),
                    _safe(m.get("relevance", ""))[:50]
                ])
            story.append(_pdf_styled_table(mitre_data, [22*mm, 45*mm, 35*mm, 72*mm], ACCENT))

        if tactics:
            story.append(Spacer(1, 2*mm))
            story.append(Paragraph("<b>Tactiques de social engineering (Cialdini)</b>", styles['SubSection']))
            tac_data = [["TACTIQUE", "PRINCIPE CIALDINI", "EFFICACITE"]]
            for tac in tactics:
                tac_data.append([
                    _safe(tac.get("tactic", "")),
                    _safe(tac.get("cialdini_principle", "")),
                    _safe(tac.get("effectiveness", "")).upper()
                ])
            story.append(_pdf_styled_table(tac_data, [55*mm, 65*mm, 54*mm], ACCENT))

        if not mitre and not tactics and classification.get("mitre_tactics"):
            story.append(Paragraph(
                f'Techniques identifiees : {", ".join(classification["mitre_tactics"])}',
                styles['Body']))

    # ════════════════════════════════════════
    # 6. RECOMMENDED RESPONSE
    # ════════════════════════════════════════
    recs = ai.get("recommended_actions", []) if ai else []
    rec_from_verdict = verdict.get("recommendation", "")

    sec += 1
    story.append(_pdf_section_header(str(sec), "RECOMMENDED RESPONSE", PRIMARY))

    # Always provide baseline recommendations based on triage
    baseline_recs = []
    if score >= 70:
        baseline_recs = [
            "Bloquer immediatement l'expediteur au niveau du filtre email",
            "Isoler et supprimer l'email de toutes les boites de reception",
            "Verifier les logs d'acces pour detecter des clics sur les liens malveillants",
            "Notifier le RSSI et escalader en incident de securite",
            "Ajouter les IOCs (URLs, IPs, domaines) aux listes de blocage",
        ]
    elif score >= 45:
        baseline_recs = [
            "Mettre l'email en quarantaine pour analyse approfondie",
            "Verifier les logs pour identifier d'autres destinataires",
            "Ajouter les IOCs suspects aux watchlists",
            "Sensibiliser les destinataires au risque de phishing",
        ]
    elif score >= 25:
        baseline_recs = [
            "Surveiller l'expediteur pour activite repetee",
            "Sensibiliser le destinataire aux signaux de phishing",
            "Documenter l'alerte pour reference future",
        ]
    else:
        baseline_recs = [
            "Aucune action immediate requise",
            "Classer comme faux positif si confirme apres verification manuelle",
        ]

    # Use AI recs if available, otherwise use baseline
    final_recs = recs if recs else baseline_recs
    if rec_from_verdict and not recs:
        for line in rec_from_verdict.split("\n"):
            cleaned = _clean_recommendation(line)
            if cleaned and cleaned not in final_recs:
                final_recs.append(cleaned)

    # Deduplicate and clean all recommendations
    seen = set()
    deduped_recs = []
    for r in final_recs:
        cleaned = _clean_recommendation(r)
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            deduped_recs.append(cleaned)

    rec_data = [["#", "ACTION", "OWNER"]]
    owners = ["SOC L1", "SOC L2", "SOC L2", "RSSI", "SOC L1"]
    for i, r in enumerate(deduped_recs[:8]):
        owner = owners[i] if i < len(owners) else "SOC"
        rec_data.append([str(i + 1), _safe(r), owner])
    story.append(_pdf_styled_table(rec_data, [10*mm, 134*mm, 30*mm], PRIMARY))

    # ════════════════════════════════════════
    # ANNEXE A — ANALYSE IA DETAILLEE
    # ════════════════════════════════════════
    if ai and not ai.get("error"):
        sem = ai.get("semantic_analysis", {})
        imp = ai.get("impersonation", {})
        soph = ai.get("sophistication", {})

        if sem or imp or soph:
            story.append(PageBreak())
            story.append(_pdf_section_header("A", "ANNEXE — ANALYSE IA DETAILLEE", TEXT_MUTED))

            ai_data = [
                ["Emotion ciblee", _safe(sem.get("target_emotion", "N/A"))],
                ["Pretexte", _safe(sem.get("pretext", imp.get("pretext", "N/A")))],
                ["Entite usurpee", _safe(imp.get("impersonated_entity", "N/A"))],
                ["Qualite usurpation", f"{imp.get('impersonation_quality', 'N/A')}/10"],
                ["Credibilite", f"{sem.get('credibility_assessment', 'N/A')}/10"],
                ["Sophistication", f"{soph.get('level', 'N/A')} ({soph.get('score', 'N/A')}/10)"],
                ["Confiance IA", f"{round((ai.get('ai_confidence', 0)) * 100)}%"],
            ]
            story.append(_pdf_info_table(ai_data, ACCENT))

    # ════════════════════════════════════════
    # ANNEXE B — EN-TETES BRUTS
    # ════════════════════════════════════════
    x_headers = headers_a.get("x_headers", {})
    if received_chain or x_headers:
        story.append(PageBreak())
        story.append(_pdf_section_header("B", "ANNEXE — EN-TETES BRUTS (PREUVE)", TEXT_MUTED))
        story.append(Paragraph(
            '<i><font color="#718096">Conservation de preuve pour analyse independante.</font></i>',
            styles['BodySmall']))
        story.append(Spacer(1, 2*mm))

        if received_chain:
            story.append(Paragraph("<b>B.1 En-tetes Received</b>", styles['SubSection']))
            for hop in received_chain:
                story.append(Paragraph(
                    f'<font face="Courier" size="6.5" color="#4a5568">'
                    f'Hop {hop.get("hop", "?")}: {_safe(hop.get("raw", ""))}</font>',
                    styles['Mono']))
                story.append(Spacer(1, 1*mm))

        if x_headers:
            story.append(Paragraph("<b>B.2 X-Headers</b>", styles['SubSection']))
            for key, value in list(x_headers.items())[:20]:
                story.append(Paragraph(
                    f'<font face="Courier" size="6.5" color="#4a5568">'
                    f'{_safe(key)}: {_safe(str(value)[:150])}</font>',
                    styles['Mono']))
                story.append(Spacer(1, 0.5*mm))

    # ════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════
    story.append(Spacer(1, 10*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(
        f'Rapport {report_number} &mdash; Incident {incident_id} &mdash; '
        f'Phishing Email Forensics &mdash; {now} &mdash; {classification["tlp"]} &mdash; CONFIDENTIEL',
        styles['Footer']))

    doc.build(story)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════
#
#   DOCX REPORT
#
# ════════════════════════════════════════════════════════════════

def generate_docx_report(analysis: dict) -> bytes:
    from docx import Document
    from docx.shared import Pt, Cm, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import nsdecls
    from docx.oxml import parse_xml

    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(1.5)
        section.bottom_margin = Cm(1.5)
        section.left_margin = Cm(2)
        section.right_margin = Cm(2)

    PRIMARY = RGBColor(0x0f, 0x34, 0x60)
    ACCENT = RGBColor(0xe9, 0x45, 0x60)
    TEXT_DARK = RGBColor(0x2d, 0x37, 0x48)
    TEXT_MUTED = RGBColor(0x71, 0x80, 0x96)
    WHITE = RGBColor(0xff, 0xff, 0xff)
    SUCCESS_RGB = RGBColor(0x27, 0xae, 0x60)
    WARNING_RGB = RGBColor(0xf3, 0x9c, 0x12)
    DANGER_RGB = RGBColor(0xe7, 0x4c, 0x3c)

    level_colors = {
        'CRITICAL': DANGER_RGB, 'HIGH': RGBColor(0xe6, 0x7e, 0x22),
        'MEDIUM': RGBColor(0x34, 0x98, 0xdb), 'LOW': SUCCESS_RGB,
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
    incident_id = _generate_incident_id(analysis)
    report_number = _generate_report_number(analysis)
    classification = _classify_incident(analysis)
    timeline = _build_timeline(analysis)
    dsec = 0  # dynamic section counter

    # ── Helpers ──
    def _set_cell_bg(cell, color_hex):
        shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
        cell._tc.get_or_add_tcPr().append(shading)

    def _section(text, num=None):
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
        border_p = doc.add_paragraph()
        border_p.paragraph_format.space_before = Pt(0)
        border_p.paragraph_format.space_after = Pt(6)
        pPr = border_p._p.get_or_add_pPr()
        pBdr = parse_xml(
            f'<w:pBdr {nsdecls("w")}>'
            f'  <w:bottom w:val="single" w:sz="6" w:space="1" w:color="0F3460"/>'
            f'</w:pBdr>')
        pPr.append(pBdr)

    def _grid_table(data):
        table = doc.add_table(rows=len(data), cols=len(data[0]))
        table.style = 'Table Grid'
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
                elif i % 2 == 0:
                    _set_cell_bg(cell, "F8F9FC")
        return table

    def _kv_table(data):
        table = doc.add_table(rows=len(data), cols=2)
        table.style = 'Table Grid'
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, (label, val) in enumerate(data):
            cl = table.rows[i].cells[0]
            cv = table.rows[i].cells[1]
            cl.text = str(label)
            cv.text = str(val or "")
            _set_cell_bg(cl, "F8F9FC")
            for p in cl.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9)
                    r.font.color.rgb = PRIMARY
                    r.bold = True
            for p in cv.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9)
                    r.font.color.rgb = TEXT_DARK
        return table

    def _note(text, italic=True, size=8, color=TEXT_MUTED):
        p = doc.add_paragraph()
        run = p.add_run(text)
        run.font.size = Pt(size)
        run.font.color.rgb = color
        if italic:
            run.italic = True

    # ════════════════════════════════════════
    # COVER
    # ════════════════════════════════════════
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
    run2 = p2.add_run(f"Rapport N° {report_number}")
    run2.font.size = Pt(12)
    run2.font.color.rgb = RGBColor(0xcb, 0xd5, 0xe0)
    run2.bold = True
    p3 = cell.add_paragraph()
    p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run3 = p3.add_run(f"Incident {incident_id} — {now} — {classification['tlp']}")
    run3.font.size = Pt(10)
    run3.font.color.rgb = RGBColor(0xcb, 0xd5, 0xe0)
    doc.add_paragraph()

    # Severity
    sev_t = doc.add_table(rows=1, cols=1)
    sev_t.alignment = WD_TABLE_ALIGNMENT.CENTER
    sc = sev_t.rows[0].cells[0]
    color_hex = f"{level_color.red:02x}{level_color.green:02x}{level_color.blue:02x}"
    _set_cell_bg(sc, color_hex)
    p = sc.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"SEVERITE: {level} — {classification['priority']} — SCORE: {score}/100")
    run.font.size = Pt(14)
    run.font.color.rgb = WHITE
    run.bold = True

    # ════════════════════════════════════════
    # §1. EXECUTIVE SUMMARY
    # ════════════════════════════════════════
    dsec += 1
    _section("EXECUTIVE SUMMARY", str(dsec))

    # One-liner
    p = doc.add_paragraph()
    one_liner = (
        f"Severity: {level} — {classification['category']} "
        f"detecte depuis {meta.get('from', 'Inconnu')} (score {score}/100)."
    )
    run = p.add_run(one_liner)
    run.bold = True
    run.font.size = Pt(10)

    # Full summary
    ai_summary = ""
    if ai and not ai.get("error"):
        ai_summary = ai.get("executive_summary", "")
    summary_text = ai_summary or verdict.get("summary", "")
    if summary_text:
        p = doc.add_paragraph()
        run = p.add_run(summary_text)
        run.font.size = Pt(9)
        run.font.color.rgb = TEXT_DARK

    # Impact line
    p = doc.add_paragraph()
    run = p.add_run("Impact : ")
    run.bold = True
    run.font.size = Pt(9)
    run = p.add_run(f"{classification['sub_category']}. ")
    run.font.size = Pt(9)
    run = p.add_run("Priorite : ")
    run.bold = True
    run.font.size = Pt(9)
    run = p.add_run(f"{classification['priority']} — {classification['severity_description']}. ")
    run.font.size = Pt(9)
    run = p.add_run("TLP : ")
    run.bold = True
    run.font.size = Pt(9)
    run = p.add_run(f"{classification['tlp']}.")
    run.font.size = Pt(9)

    # ════════════════════════════════════════
    # 2. ALERT DETAILS
    # ════════════════════════════════════════
    dsec += 1
    _section("ALERT DETAILS", str(dsec))
    _kv_table([
        ("N° Rapport", report_number),
        ("N° Incident", incident_id),
        ("Date du rapport", now),
        ("Sujet", meta.get("subject", "N/A")),
        ("Expediteur", meta.get("from", "N/A")),
        ("Destinataire(s)", meta.get("to", "N/A")),
        ("Date reception", meta.get("date", "N/A")),
        ("Message-ID", meta.get("message_id", "N/A")),
        ("Return-Path", meta.get("return_path", "N/A")),
        ("Categorie", classification["category"]),
        ("Score", f"{score}/100 ({level})"),
    ])

    # Timeline
    doc.add_paragraph()
    h = doc.add_paragraph()
    run = h.add_run("Chronologie")
    run.bold = True
    run.font.size = Pt(10)
    run.font.color.rgb = PRIMARY

    tl_rows = [["Phase", "Horodatage", "Description"]]
    for phase, ts, desc in timeline:
        tl_rows.append([phase, str(ts)[:30], desc])
    _grid_table(tl_rows)

    # ════════════════════════════════════════
    # 3. TRIAGE DECISION
    # ════════════════════════════════════════
    dsec += 1
    _section("TRIAGE DECISION", str(dsec))

    if score >= 45:
        tv, tr = "TRUE POSITIVE", f"{classification['category'].lower()} avec score {score}/100."
        tc = "E74C3C"
    elif score >= 25:
        tv, tr = "SUSPICIOUS", f"Elements suspects (score {score}/100). Investigation requise."
        tc = "F39C12"
    else:
        tv, tr = "PROBABLE FALSE POSITIVE", f"Score faible ({score}/100). Aucun IOC significatif."
        tc = "27AE60"

    triage_banner = doc.add_table(rows=1, cols=1)
    triage_banner.alignment = WD_TABLE_ALIGNMENT.CENTER
    tcell = triage_banner.rows[0].cells[0]
    _set_cell_bg(tcell, tc)
    p = tcell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(tv)
    run.font.size = Pt(13)
    run.font.color.rgb = WHITE
    run.bold = True

    p = doc.add_paragraph()
    run = p.add_run(tr)
    run.font.size = Pt(9)

    # Scoring factors
    factors = risk.get("factors", [])
    if factors:
        h = doc.add_paragraph()
        run = h.add_run("Facteurs de risque")
        run.bold = True
        run.font.size = Pt(10)
        for f in factors:
            doc.add_paragraph(f, style='List Bullet')

    # Auth
    h = doc.add_paragraph()
    run = h.add_run("Authentification email")
    run.bold = True
    run.font.size = Pt(10)

    auth_rows = [["Protocole", "Statut", "Details"]]
    for proto in ['spf', 'dkim', 'dmarc']:
        item = auth.get(proto, {})
        auth_rows.append([proto.upper(), item.get("status", "absent").upper(),
                         (item.get("details", "") or "")[:70]])
    table = _grid_table(auth_rows)
    for i, proto in enumerate(['spf', 'dkim', 'dmarc'], 1):
        status = auth.get(proto, {}).get("status", "absent")
        cell = table.rows[i].cells[1]
        for p in cell.paragraphs:
            for r in p.runs:
                if status == "pass": r.font.color.rgb = SUCCESS_RGB
                elif status in ("fail", "softfail"): r.font.color.rgb = DANGER_RGB
                else: r.font.color.rgb = WARNING_RGB
                r.bold = True

    anomalies = headers_a.get("anomalies", [])
    if anomalies:
        h = doc.add_paragraph()
        run = h.add_run("Anomalies")
        run.bold = True
        run.font.size = Pt(10)
        for a in anomalies:
            doc.add_paragraph(a, style='List Bullet')

    # ════════════════════════════════════════
    # 4. ENRICHMENT FINDINGS
    # ════════════════════════════════════════
    doc.add_page_break()
    dsec += 1
    _section("ENRICHMENT FINDINGS", str(dsec))
    _note("IOCs au format defange (hxxps, [.]) pour partage securise.")

    urls = iocs.get("urls", [])
    if urls:
        doc.add_heading("4.1 URLs detectees", level=2)
        url_rows = [["URL (defanged)", "Flags"]]
        for u in urls[:15]:
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("Shortener")
            if u.get("mismatched_display"): flags.append("Lien masque")
            url_rows.append([_defang_url(u.get("url", ""))[:65], ", ".join(flags) or "—"])
        _grid_table(url_rows)

    ips_list = iocs.get("ips", [])
    if ips_list:
        doc.add_heading("4.2 Adresses IP", level=2)
        ip_rows = [["IP (defanged)", "Type", "Threat Intel"]]
        for ip_info in ips_list[:10]:
            ip_rows.append([
                _defang_ip(ip_info.get("ip", "")),
                "Privee" if ip_info.get('is_private') else "Publique",
                f"VT: rechercher {_defang_ip(ip_info.get('ip', ''))}"
            ])
        _grid_table(ip_rows)

    received_chain = headers_a.get("received_chain", [])
    if received_chain:
        doc.add_heading("4.3 Chaine de transmission", level=2)
        _note(f"L'email a traverse {len(received_chain)} serveur(s).", italic=False, size=9, color=TEXT_DARK)
        hop_rows = [["Hop", "IP(s)", "Details"]]
        for hop in received_chain:
            ips_str = ", ".join(_defang_ip(ip) for ip in hop.get("ips_found", [])) or "—"
            hop_rows.append([str(hop.get("hop", "")), ips_str, hop.get("raw", "")[:120]])
        _grid_table(hop_rows)

    kws = iocs.get("phishing_keywords", [])
    if kws:
        doc.add_heading("4.4 Mots-cles phishing", level=2)
        doc.add_paragraph(", ".join(kws))

    if atts:
        doc.add_heading("4.5 Pieces jointes", level=2)
        for att in atts:
            _kv_table([
                ("Fichier", att.get("filename", "")),
                ("Type MIME", att.get("content_type", "")),
                ("Taille", _format_bytes(att.get("size_bytes", 0))),
                ("Statut", "SUSPECT" if att.get("suspicious_extension") else "Normal"),
                ("MD5", att.get("md5", "N/A")),
                ("SHA256", att.get("sha256", "N/A")),
            ])
            sha256 = att.get("sha256", "")
            if sha256 and sha256 != "N/A":
                _note(f"VirusTotal: hxxps[://]www[.]virustotal[.]com/gui/file/{sha256}", size=7)
            doc.add_paragraph()

    # ════════════════════════════════════════
    # 5. MITRE ATT&CK MAPPING
    # ════════════════════════════════════════
    mitre = ai.get("mitre_techniques", []) if ai else []
    tactics = ai.get("social_engineering_tactics", []) if ai else []
    if mitre or tactics:
        dsec += 1
        _section("MITRE ATT&CK MAPPING", str(dsec))
        if mitre:
            mitre_rows = [["ID", "Technique", "Tactic", "Pertinence"]]
            for m in mitre:
                mitre_rows.append([m.get("id", ""), m.get("name", ""),
                                  m.get("tactic", "Initial Access"), m.get("relevance", "")[:50]])
            _grid_table(mitre_rows)

        if tactics:
            doc.add_heading("Tactiques de social engineering", level=2)
            tac_rows = [["Tactique", "Principe Cialdini", "Efficacite"]]
            for tac in tactics:
                tac_rows.append([tac.get("tactic", ""), tac.get("cialdini_principle", ""),
                                tac.get("effectiveness", "").upper()])
            _grid_table(tac_rows)

    # ════════════════════════════════════════
    # 6. RECOMMENDED RESPONSE
    # ════════════════════════════════════════
    dsec += 1
    _section("RECOMMENDED RESPONSE", str(dsec))

    recs = ai.get("recommended_actions", []) if ai else []
    rec_from_verdict = verdict.get("recommendation", "")
    if score >= 70:
        baseline = [
            "Bloquer l'expediteur au niveau du filtre email",
            "Isoler et supprimer l'email de toutes les boites",
            "Verifier les logs pour detecter des clics",
            "Notifier le RSSI et escalader",
            "Ajouter les IOCs aux listes de blocage",
        ]
    elif score >= 45:
        baseline = [
            "Mettre l'email en quarantaine",
            "Verifier les logs pour autres destinataires",
            "Ajouter les IOCs aux watchlists",
            "Sensibiliser les destinataires",
        ]
    elif score >= 25:
        baseline = [
            "Surveiller l'expediteur",
            "Sensibiliser le destinataire",
            "Documenter l'alerte",
        ]
    else:
        baseline = [
            "Aucune action immediate requise",
            "Classer comme faux positif si confirme",
        ]

    final_recs = recs if recs else baseline
    if rec_from_verdict and not recs:
        for line in rec_from_verdict.split("\n"):
            cleaned = _clean_recommendation(line)
            if cleaned and cleaned not in final_recs:
                final_recs.append(cleaned)

    # Deduplicate and clean
    seen = set()
    deduped = []
    for r in final_recs:
        cleaned = _clean_recommendation(r)
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            deduped.append(cleaned)

    owners = ["SOC L1", "SOC L2", "SOC L2", "RSSI", "SOC L1"]
    rec_rows = [["#", "Action", "Owner"]]
    for i, r in enumerate(deduped[:8]):
        owner = owners[i] if i < len(owners) else "SOC"
        rec_rows.append([str(i + 1), r, owner])
    _grid_table(rec_rows)

    # ════════════════════════════════════════
    # ANNEXE A — AI DETAILS
    # ════════════════════════════════════════
    if ai and not ai.get("error"):
        sem = ai.get("semantic_analysis", {})
        imp = ai.get("impersonation", {})
        soph = ai.get("sophistication", {})
        if sem or imp or soph:
            doc.add_page_break()
            _section("ANNEXE — ANALYSE IA DETAILLEE", "A")
            _kv_table([
                ("Emotion ciblee", sem.get("target_emotion", "N/A")),
                ("Pretexte", sem.get("pretext", imp.get("pretext", "N/A"))),
                ("Entite usurpee", imp.get("impersonated_entity", "N/A")),
                ("Sophistication", f"{soph.get('level', 'N/A')} ({soph.get('score', 'N/A')}/10)"),
                ("Confiance IA", f"{round(ai.get('ai_confidence', 0) * 100)}%"),
            ])

    # ════════════════════════════════════════
    # ANNEXE B — RAW HEADERS
    # ════════════════════════════════════════
    x_headers = headers_a.get("x_headers", {})
    if received_chain or x_headers:
        doc.add_page_break()
        _section("ANNEXE — EN-TETES BRUTS (PREUVE)", "B")
        _note("Conservation de preuve pour analyse independante.")

        if received_chain:
            doc.add_heading("B.1 En-tetes Received", level=2)
            for hop in received_chain:
                p = doc.add_paragraph()
                run = p.add_run(f"Hop {hop.get('hop', '?')}: {hop.get('raw', '')}")
                run.font.size = Pt(7)
                run.font.name = 'Courier New'
                run.font.color.rgb = RGBColor(0x4a, 0x55, 0x68)

        if x_headers:
            doc.add_heading("B.2 X-Headers", level=2)
            for key, value in list(x_headers.items())[:20]:
                p = doc.add_paragraph()
                run = p.add_run(f"{key}: {str(value)[:150]}")
                run.font.size = Pt(7)
                run.font.name = 'Courier New'
                run.font.color.rgb = RGBColor(0x4a, 0x55, 0x68)

    # ════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════
    doc.add_paragraph()
    footer = doc.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run(
        f"Rapport {report_number} — Incident {incident_id} — "
        f"Phishing Email Forensics — {now} — {classification['tlp']} — CONFIDENTIEL")
    run.font.size = Pt(8)
    run.font.color.rgb = TEXT_MUTED

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ════════════════════════════════════════
# PDF Helper functions
# ════════════════════════════════════════

def _pdf_section_header(num, title, color):
    from reportlab.lib.units import mm
    from reportlab.platypus import Table, TableStyle, Paragraph
    from reportlab.lib.styles import ParagraphStyle

    style = ParagraphStyle('sh', fontSize=12, fontName='Helvetica-Bold',
                           textColor=color, leading=16)
    content = Paragraph(f"{num}. {title}", style)
    t = Table([[content]], colWidths=[174*mm], rowHeights=[10*mm])
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LINEBELOW', (0, 0), (-1, -1), 1.5, color),
    ]))
    return t


def _pdf_styled_table(data, col_widths, header_color):
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


def _pdf_info_table(data, label_color):
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import Table, TableStyle

    t = Table(data, colWidths=[42*mm, 132*mm])
    t.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), label_color),
        ('TEXTCOLOR', (1, 0), (1, -1), HexColor('#2d3748')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.4, HexColor('#e2e8f0')),
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8f9fc')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    return t
