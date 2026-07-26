#!/usr/bin/env python3
"""
Phishing Email Forensics Analyzer
==================================
Analyse automatisée de fichiers .eml pour la détection de phishing.

Fonctionnalités :
- Parsing complet des headers email
- Vérification SPF / DKIM / DMARC
- Extraction d'IOCs (URLs, domaines, IPs, hashes de pièces jointes)
- Scoring de risque phishing
- Génération de rapport JSON

Usage :
    python phishing_analyzer.py <fichier.eml>
    python phishing_analyzer.py <dossier_contenant_emls>
    python phishing_analyzer.py <fichier.eml> --ai
    python phishing_analyzer.py --demo --ai
"""

import email
import email.policy
import re
import hashlib
import json
import sys
import os
from datetime import datetime
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from collections import Counter


# ──────────────────────────────────────────────
# Configuration & Patterns
# ──────────────────────────────────────────────

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]},;]+', re.IGNORECASE
)
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
)
RECEIVED_IP_PATTERN = re.compile(
    r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
)

# Mots-clés suspects fréquents dans le phishing
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "click here", "confirm your identity",
    "suspended", "unauthorized", "security alert", "update your information",
    "password expired", "act now", "limited time", "reset your password",
    "unusual activity", "verify immediately", "your account has been",
    "compromised", "validate", "expire", "deactivate",
    # Français
    "vérifiez votre compte", "cliquez ici", "confirmez votre identité",
    "suspendu", "non autorisé", "alerte de sécurité", "mettez à jour",
    "mot de passe expiré", "agissez maintenant", "temps limité",
    "activité inhabituelle", "vérifiez immédiatement", "votre compte a été",
    "compromis", "valider", "expirer", "désactiver"
]

# Domaines de messagerie gratuits (souvent usurpés)
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "yandex.com",
    "zoho.com", "icloud.com", "gmx.com", "tutanota.com"
]

# TLDs suspects
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".buzz", ".work", ".click", ".link", ".info", ".icu",
    ".cam", ".rest", ".surf"
]


# ──────────────────────────────────────────────
# Classe principale
# ──────────────────────────────────────────────

class PhishingAnalyzer:
    """Analyseur forensique d'emails de phishing."""

    def __init__(self, eml_path: str):
        self.eml_path = eml_path
        self.msg = None
        self._msg_obj = None  # extract-msg object for .msg files
        self._is_msg = False
        self.report = {
            "metadata": {},
            "headers_analysis": {},
            "authentication": {},
            "iocs": {},
            "attachments": [],
            "risk_scoring": {},
            "verdict": {}
        }

    def load_email(self) -> bool:
        """Charge et parse le fichier .eml ou .msg."""
        try:
            # Detect .msg by magic bytes (OLE2 Compound Document)
            with open(self.eml_path, 'rb') as f:
                magic = f.read(8)

            if magic[:4] == b'\xd0\xcf\x11\xe0':  # OLE2 magic
                return self._load_msg()
            else:
                return self._load_eml()
        except Exception as e:
            print(f"[ERREUR] Impossible de charger {self.eml_path}: {e}")
            return False

    def _load_eml(self) -> bool:
        """Parse un fichier .eml standard (RFC 822)."""
        try:
            with open(self.eml_path, 'rb') as f:
                self.msg = BytesParser(policy=policy.default).parse(f)
            self._is_msg = False
            return True
        except Exception as e:
            print(f"[ERREUR] Échec parsing .eml: {e}")
            return False

    def _load_msg(self) -> bool:
        """Parse un fichier .msg (Outlook) via extract-msg, puis convertit en email.Message."""
        try:
            import extract_msg
            msg_obj = extract_msg.Message(self.eml_path)
            self._msg_obj = msg_obj
            self._is_msg = True

            # Build a standard email.Message from .msg data for uniform processing
            from email.message import EmailMessage
            em = EmailMessage()

            em['Subject'] = msg_obj.subject or ''
            em['From'] = msg_obj.sender or ''
            em['To'] = msg_obj.to or ''
            if msg_obj.cc:
                em['Cc'] = msg_obj.cc
            if msg_obj.date:
                em['Date'] = str(msg_obj.date)
            if hasattr(msg_obj, 'messageId') and msg_obj.messageId:
                em['Message-ID'] = msg_obj.messageId

            # Copy all headers from .msg headerDict
            if msg_obj.headerDict:
                for key, value in msg_obj.headerDict.items():
                    if key.lower() not in ('subject', 'from', 'to', 'cc', 'date', 'message-id'):
                        try:
                            # Handle multi-value headers (e.g. Received)
                            if isinstance(value, list):
                                for v in value:
                                    em.append(key, str(v).strip())
                            else:
                                em[key] = str(value).strip()
                        except Exception:
                            pass

            # Also try to parse raw headers from .msg header property
            # This is critical for extracting Received headers and IPs
            received_count = len(em.get_all('Received') or [])
            if hasattr(msg_obj, 'header') and msg_obj.header:
                raw_header = str(msg_obj.header)
                # Parse Received headers using line continuation (lines starting with space/tab)
                import re as _re
                lines = raw_header.split('\n')
                current_header = ''
                for line in lines:
                    if line.startswith((' ', '\t')) and current_header:
                        current_header += ' ' + line.strip()
                    else:
                        if current_header.lower().startswith('received:'):
                            try:
                                em.append('Received', current_header.split(':', 1)[1].strip())
                            except Exception:
                                pass
                        current_header = line.strip()
                # Don't forget the last one
                if current_header.lower().startswith('received:'):
                    try:
                        em.append('Received', current_header.split(':', 1)[1].strip())
                    except Exception:
                        pass

            # Also extract Return-Path if missing
            if not em.get('Return-Path') and hasattr(msg_obj, 'header') and msg_obj.header:
                rp_match = _re.search(r'Return-Path:\s*<?([^>\s]+)>?', str(msg_obj.header), _re.I)
                if rp_match:
                    em['Return-Path'] = rp_match.group(1)

            new_received = len(em.get_all('Received') or [])
            print(f"[MSG] Headers parsed: {received_count} -> {new_received} Received headers")

            # Set body
            body = msg_obj.body or ''
            html_body = msg_obj.htmlBody
            if html_body:
                if isinstance(html_body, bytes):
                    html_body = html_body.decode('utf-8', errors='replace')
                em.set_content(body)
                em.add_alternative(html_body, subtype='html')
            else:
                em.set_content(body)

            self.msg = em
            print(f"[MSG] Fichier .msg parsé: {msg_obj.subject}")
            return True
        except ImportError:
            print("[ERREUR] Module extract-msg non installé. Installez avec: pip install extract-msg")
            return False
        except Exception as e:
            print(f"[ERREUR] Échec parsing .msg: {e}")
            return False

    def analyze(self, enable_ai=False) -> dict:
        """Lance l'analyse complète."""
        if not self.load_email():
            return {"error": f"Échec du chargement de {self.eml_path}"}

        self._extract_metadata()
        self._analyze_headers()
        self._check_authentication()
        self._analyze_attachments()   # avant _extract_iocs pour merger les IOCs des PJ
        self._extract_iocs()
        self._sandbox_urls()          # captures d'ecran des URLs suspectes
        self._whois_from_domain()     # Whois du domaine expediteur
        self._generate_impact_analysis()  # scenario victime + MITRE ATT&CK
        self._calculate_risk_score()

        # Analyse IA si activée
        if enable_ai:
            self._run_ai_analysis()

        return self.report

    def _run_ai_analysis(self):
        """Lance l'analyse IA enrichie."""
        try:
            from ai_analyzer import create_analyzer
            print("[AI] Lancement de l'analyse IA...")

            ai = create_analyzer()
            email_data = {
                "body_text": self._get_body_text(),
                "body_html": self._get_body_html()
            }
            ai_result = ai.analyze(email_data, self.report)
            self.report["ai_analysis"] = ai_result

            if "error" not in ai_result:
                print(f"[AI] Analyse terminée — confiance: {ai_result.get('ai_confidence', 'N/A')}")
            else:
                print(f"[AI] Analyse partielle — {ai_result.get('error', '')}")
        except ImportError:
            print("[AI] Module ai_analyzer.py non trouvé — analyse IA ignorée")
        except Exception as e:
            print(f"[AI] Erreur: {e}")
            self.report["ai_analysis"] = {"error": str(e)}

    # ── Métadonnées ──

    def _extract_metadata(self):
        """Extrait les métadonnées de base de l'email."""
        self.report["metadata"] = {
            "file": os.path.basename(self.eml_path),
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "subject": str(self.msg.get("Subject", "")),
            "from": str(self.msg.get("From", "")),
            "to": str(self.msg.get("To", "")),
            "cc": str(self.msg.get("Cc", "")),
            "date": str(self.msg.get("Date", "")),
            "message_id": str(self.msg.get("Message-ID", "")),
            "reply_to": str(self.msg.get("Reply-To", "")),
            "return_path": str(self.msg.get("Return-Path", ""))
        }

    # ── Analyse des headers ──

    def _analyze_headers(self):
        """Analyse approfondie des headers."""
        headers = {}

        # Chaîne Received (traçabilité du routage)
        received_headers = self.msg.get_all("Received", [])
        hops = []
        for i, r in enumerate(received_headers):
            ips = RECEIVED_IP_PATTERN.findall(r)
            hops.append({
                "hop": i + 1,
                "raw": r.strip()[:200],
                "ips_found": ips
            })
        headers["received_chain"] = hops
        headers["total_hops"] = len(hops)

        # Vérification From vs Return-Path
        from_addr = self._extract_email_address(str(self.msg.get("From", "")))
        return_path = self._extract_email_address(str(self.msg.get("Return-Path", "")))
        reply_to = self._extract_email_address(str(self.msg.get("Reply-To", "")))

        headers["from_address"] = from_addr
        headers["return_path_address"] = return_path
        headers["reply_to_address"] = reply_to

        # Vérifier les incohérences
        anomalies = []
        if from_addr and return_path and from_addr.lower() != return_path.lower():
            anomalies.append(f"From ({from_addr}) ≠ Return-Path ({return_path})")
        if from_addr and reply_to and from_addr.lower() != reply_to.lower():
            anomalies.append(f"From ({from_addr}) ≠ Reply-To ({reply_to})")

        # Vérifier si le domaine expéditeur est un fournisseur gratuit
        from_domain = from_addr.split("@")[-1] if from_addr and "@" in from_addr else ""
        if from_domain.lower() in FREE_EMAIL_PROVIDERS:
            anomalies.append(f"Expéditeur utilise un fournisseur email gratuit: {from_domain}")

        # Vérifier si Reply-To utilise un fournisseur gratuit alors que From est corporate
        reply_to_domain = reply_to.split("@")[-1].lower() if reply_to and "@" in reply_to else ""
        if reply_to_domain in FREE_EMAIL_PROVIDERS and from_domain.lower() not in FREE_EMAIL_PROVIDERS:
            anomalies.append(f"Reply-To utilise un email gratuit ({reply_to}) alors que From est corporate ({from_domain})")

        headers["anomalies"] = anomalies

        # X-Headers intéressants
        x_headers = {}
        for key in self.msg.keys():
            if key.lower().startswith("x-"):
                x_headers[key] = str(self.msg.get(key, ""))[:200]
        headers["x_headers"] = x_headers

        self.report["headers_analysis"] = headers

    # ── Authentification (SPF / DKIM / DMARC) ──

    def _check_authentication(self):
        """Vérifie les résultats d'authentification dans les headers."""
        auth = {
            "spf": {"status": "absent", "details": ""},
            "dkim": {"status": "absent", "details": ""},
            "dmarc": {"status": "absent", "details": ""},
            "arc": {"status": "absent", "details": ""}
        }

        # Authentication-Results header
        auth_results = str(self.msg.get("Authentication-Results", ""))
        if auth_results:
            # SPF
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', auth_results, re.I)
            if spf_match:
                auth["spf"]["status"] = spf_match.group(1).lower()
                auth["spf"]["details"] = auth_results

            # DKIM
            dkim_match = re.search(r'dkim=(pass|fail|neutral|none|temperror|permerror)', auth_results, re.I)
            if dkim_match:
                auth["dkim"]["status"] = dkim_match.group(1).lower()
                auth["dkim"]["details"] = auth_results

            # DMARC
            dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass|permerror|temperror)', auth_results, re.I)
            if dmarc_match:
                auth["dmarc"]["status"] = dmarc_match.group(1).lower()
                auth["dmarc"]["details"] = auth_results

        # Received-SPF header (alternative)
        received_spf = str(self.msg.get("Received-SPF", ""))
        if received_spf and auth["spf"]["status"] == "absent":
            spf_match = re.search(r'^(pass|fail|softfail|neutral|none)', received_spf, re.I)
            if spf_match:
                auth["spf"]["status"] = spf_match.group(1).lower()
                auth["spf"]["details"] = received_spf

        # DKIM-Signature presence
        dkim_sig = self.msg.get("DKIM-Signature", "")
        if dkim_sig:
            auth["dkim"]["signature_present"] = True

        # ARC headers
        arc_result = str(self.msg.get("ARC-Authentication-Results", ""))
        if arc_result:
            auth["arc"]["status"] = "present"
            auth["arc"]["details"] = arc_result[:300]

        self.report["authentication"] = auth

    # ── Extraction IOCs ──

    def _extract_iocs(self):
        """Extrait tous les indicateurs de compromission (body + headers + pièces jointes)."""
        body_text = self._get_body_text()
        body_html = self._get_body_html()
        full_content = body_text + " " + body_html

        # URLs from body
        urls = list(set(URL_PATTERN.findall(full_content)))
        url_analysis = []
        seen_urls = set()
        for url in urls:
            parsed = urlparse(url)
            url_info = {
                "url": url,
                "domain": parsed.netloc,
                "scheme": parsed.scheme,
                "path": parsed.path,
                "suspicious_tld": any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS),
                "ip_based": bool(IP_PATTERN.match(parsed.netloc)),
                "url_shortener": self._is_url_shortener(parsed.netloc),
                "mismatched_display": False,
                "source": "body"
            }
            url_analysis.append(url_info)
            seen_urls.add(url)

        # Vérifier les liens masqués (href ≠ texte affiché)
        if body_html:
            href_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', re.I)
            for href, display_text in href_pattern.findall(body_html):
                display_urls = URL_PATTERN.findall(display_text)
                if display_urls:
                    for du in display_urls:
                        if urlparse(du).netloc != urlparse(href).netloc:
                            for ua in url_analysis:
                                if ua["url"] == href:
                                    ua["mismatched_display"] = True
                                    ua["display_text"] = display_text.strip()

        # Merge URLs from attachment scans
        att_iocs = self.report.get("_attachment_iocs", {})
        for att_url in att_iocs.get("urls", []):
            if att_url["url"] not in seen_urls:
                url_analysis.append(att_url)
                seen_urls.add(att_url["url"])

        # IPs from body
        ips = list(set(IP_PATTERN.findall(full_content)))
        ip_analysis = []
        seen_ips = set()
        for ip in ips:
            ip_analysis.append({"ip": ip, "is_private": self._is_private_ip(ip), "source": "body"})
            seen_ips.add(ip)

        # IPs from Received headers (relay chain)
        received_headers = self.msg.get_all("Received") if self.msg else []
        if received_headers:
            print(f"[IOC] Found {len(received_headers)} Received headers")
            for hdr in received_headers:
                header_ips = IP_PATTERN.findall(str(hdr))
                for ip in header_ips:
                    if ip not in seen_ips:
                        ip_analysis.append({"ip": ip, "is_private": self._is_private_ip(ip), "source": "header"})
                        seen_ips.add(ip)
        else:
            print("[IOC] No Received headers found")

        # Fallback: extract IPs from ALL headers if .msg (headers might be in other fields)
        if self._is_msg and self._msg_obj and not ip_analysis:
            print("[IOC] Fallback: scanning raw .msg headers for IPs")
            raw = str(getattr(self._msg_obj, 'header', '')) + str(getattr(self._msg_obj, 'headerDict', ''))
            fallback_ips = IP_PATTERN.findall(raw)
            for ip in fallback_ips:
                if ip not in seen_ips and not ip.startswith('0.') and not ip.startswith('255.'):
                    ip_analysis.append({"ip": ip, "is_private": self._is_private_ip(ip), "source": "header"})
                    seen_ips.add(ip)
            if fallback_ips:
                print(f"[IOC] Fallback found {len(ip_analysis)} IPs")

        # Merge IPs from attachment scans
        for att_ip in att_iocs.get("ips", []):
            if att_ip["ip"] not in seen_ips:
                ip_analysis.append(att_ip)
                seen_ips.add(att_ip["ip"])

        # Domaines (extraits des URLs + du contenu)
        domains = list(set(DOMAIN_PATTERN.findall(full_content)))
        domains = [d for d in domains if len(d) > 4 and "." in d]

        self.report["iocs"] = {
            "urls": url_analysis,
            "urls_count": len(url_analysis),
            "ips": ip_analysis,
            "ips_count": len(ip_analysis),
            "ip_addresses": ip_analysis,  # alias for dashboard compatibility
            "domains": domains[:50],
            "domains_count": len(domains),
            "suspicious_urls_count": sum(
                1 for u in url_analysis
                if u["suspicious_tld"] or u["ip_based"] or u["url_shortener"] or u["mismatched_display"]
            ),
            "attachment_scripts_detected": att_iocs.get("scripts_detected", False),
            "attachment_urls_count": len(att_iocs.get("urls", []))
        }

        # Analyse des mots-clés phishing (body + attachment content)
        keywords_found = []
        lower_content = full_content.lower()
        for kw in PHISHING_KEYWORDS:
            if kw.lower() in lower_content:
                keywords_found.append(kw)

        self.report["iocs"]["phishing_keywords"] = keywords_found
        self.report["iocs"]["keywords_count"] = len(keywords_found)

        # HTML attachment deep analysis results
        html_analysis = att_iocs.get("html_analysis")
        if html_analysis:
            self.report["iocs"]["html_attachment_analysis"] = html_analysis

        # Threat Intelligence enrichment (IPs, URLs, hashes)
        self._enrich_threat_intel(ip_analysis, url_analysis)

    def _enrich_threat_intel(self, ip_list: list, url_list: list):
        """Enrichit IPs et URLs via APIs Threat Intel + rDNS local."""
        import socket

        # Import threat_intel module (optional)
        try:
            from scripts.threat_intel import enrich_ip, enrich_url, enrich_hash, get_available_apis
            ti_available = True
        except ImportError:
            try:
                from threat_intel import enrich_ip, enrich_url, enrich_hash, get_available_apis
                ti_available = True
            except ImportError:
                ti_available = False

        # ── IP Enrichment ──
        enriched_ips = []
        for ip_entry in ip_list:
            ip = ip_entry["ip"]
            enrichment = {
                "ip": ip,
                "source": ip_entry.get("source", "unknown"),
                "is_private": ip_entry.get("is_private", False),
                "classification": "private" if ip_entry.get("is_private") else "public",
                "reverse_dns": None,
                "risk_indicators": [],
                "geo": {},
                "abuse": {},
                "vt": {},
            }

            if not ip_entry.get("is_private"):
                # Reverse DNS (always available)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    enrichment["reverse_dns"] = hostname
                    lower_host = hostname.lower()
                    if any(kw in lower_host for kw in ['dynamic', 'dhcp', 'pool', 'residential', 'cable', 'dsl']):
                        enrichment["risk_indicators"].append("IP residentielle/dynamique")
                    if any(kw in lower_host for kw in ['vps', 'cloud', 'server', 'host', 'dedicated']):
                        enrichment["risk_indicators"].append("IP hebergeur/VPS")
                    if not any(kw in lower_host for kw in ['mx', 'mail', 'smtp', 'mta', 'relay', 'postfix', 'sendmail']):
                        enrichment["risk_indicators"].append("Pas de reference mail dans le rDNS")
                except Exception:
                    enrichment["reverse_dns"] = "Non resolvable"
                    enrichment["risk_indicators"].append("Pas de rDNS")

                # Known providers from rDNS
                known_providers = {
                    'google': 'Google/Gmail', 'microsoft': 'Microsoft/O365', 'outlook': 'Microsoft',
                    'yahoo': 'Yahoo', 'protonmail': 'ProtonMail', 'orange': 'Orange',
                    'ovh': 'OVH', 'amazon': 'AWS', 'cloudflare': 'Cloudflare'
                }
                rdns = (enrichment["reverse_dns"] or "").lower()
                for key, provider in known_providers.items():
                    if key in rdns:
                        enrichment["provider"] = provider
                        break

                # Threat Intel APIs
                if ti_available:
                    ti_data = enrich_ip(ip, is_private=False)
                    enrichment["geo"] = ti_data.get("geo", {})
                    enrichment["abuse"] = ti_data.get("abuse", {})
                    enrichment["vt"] = ti_data.get("vt", {})

                    # Add risk indicators from API data
                    abuse = enrichment["abuse"]
                    if abuse.get("abuse_score", 0) >= 50:
                        enrichment["risk_indicators"].append(
                            f"AbuseIPDB: score {abuse['abuse_score']}% ({abuse.get('total_reports', 0)} signalements)")
                    if abuse.get("is_tor"):
                        enrichment["risk_indicators"].append("Noeud Tor detecte")

                    vt = enrichment["vt"]
                    if vt.get("malicious", 0) > 0:
                        enrichment["risk_indicators"].append(
                            f"VirusTotal: {vt['malicious']} detections malveillantes")

            enriched_ips.append(enrichment)

        self.report["iocs"]["ip_enrichment"] = enriched_ips

        # ── URL Enrichment (suspicious URLs only, to save API quota) ──
        enriched_urls = []
        for url_entry in url_list:
            if url_entry.get("suspicious_tld") or url_entry.get("ip_based") or \
               url_entry.get("url_shortener") or url_entry.get("mismatched_display"):
                url_enrich = {"url": url_entry["url"], "urlhaus": {}, "vt": {}}
                if ti_available:
                    ti_data = enrich_url(url_entry["url"])
                    url_enrich["urlhaus"] = ti_data.get("urlhaus", {})
                    url_enrich["vt"] = ti_data.get("vt", {})
                enriched_urls.append(url_enrich)

        if enriched_urls:
            self.report["iocs"]["url_enrichment"] = enriched_urls

        # ── Attachment hash enrichment ──
        enriched_hashes = []
        for att in self.report.get("attachments", []):
            if att.get("suspicious_extension"):
                hash_enrich = {
                    "filename": att["filename"],
                    "sha256": att["sha256"],
                    "md5": att["md5"],
                    "vt": {},
                    "urlhaus": {},
                }
                if ti_available:
                    vt_data = enrich_hash(att["sha256"], "sha256")
                    hash_enrich["vt"] = vt_data.get("vt", {})
                    uh_data = enrich_hash(att["md5"], "md5")
                    hash_enrich["urlhaus"] = uh_data.get("urlhaus", {})
                enriched_hashes.append(hash_enrich)

        if enriched_hashes:
            self.report["iocs"]["hash_enrichment"] = enriched_hashes

        # ── APIs status ──
        if ti_available:
            self.report["iocs"]["threat_intel_apis"] = get_available_apis()

    # ── Pièces jointes ──

    def _analyze_attachments(self):
        """Analyse les pièces jointes (.eml et .msg), y compris scan du contenu HTML."""
        attachments = []
        attachment_iocs = {"urls": [], "ips": [], "scripts_detected": False}

        # .msg files: use extract-msg attachment objects directly
        if self._is_msg and self._msg_obj:
            for att_obj in self._msg_obj.attachments:
                filename = att_obj.longFilename or att_obj.shortFilename or "unnamed"
                data = att_obj.data or b''
                if data:
                    import mimetypes
                    content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
                    att = {
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": len(data),
                        "md5": hashlib.md5(data).hexdigest(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "suspicious_extension": self._is_suspicious_extension(filename)
                    }
                    # Scan HTML/HTM attachment content for IOCs
                    if filename.lower().endswith(('.html', '.htm', '.svg')):
                        self._scan_attachment_content(data, attachment_iocs)
                    # Analyze image metadata
                    if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff')):
                        img_meta = self._extract_image_metadata(data, filename)
                        if img_meta:
                            att["image_analysis"] = img_meta
                    attachments.append(att)
        elif self.msg.is_multipart():
            for part in self.msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if "attachment" in content_disposition or part.get_filename():
                    filename = part.get_filename() or "unnamed"
                    content = part.get_payload(decode=True)
                    if content:
                        att = {
                            "filename": filename,
                            "content_type": part.get_content_type(),
                            "size_bytes": len(content),
                            "md5": hashlib.md5(content).hexdigest(),
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "suspicious_extension": self._is_suspicious_extension(filename)
                        }
                        # Scan HTML/HTM attachment content for IOCs
                        if filename.lower().endswith(('.html', '.htm', '.svg')):
                            self._scan_attachment_content(content, attachment_iocs)
                        # Analyze image metadata
                        if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff')):
                            img_meta = self._extract_image_metadata(content, filename)
                            if img_meta:
                                att["image_analysis"] = img_meta
                        attachments.append(att)

        self.report["attachments"] = attachments
        self.report["_attachment_iocs"] = attachment_iocs

    def _extract_image_metadata(self, data: bytes, filename: str) -> dict:
        """Extrait les metadonnees d'une image (dimensions, format, EXIF basique)."""
        meta = {
            "filename": filename,
            "size_bytes": len(data),
            "format": None,
            "dimensions": None,
            "has_exif": False,
            "suspicious_indicators": [],
        }

        # Detect format from magic bytes
        if data[:3] == b'\xff\xd8\xff':
            meta["format"] = "JPEG"
        elif data[:8] == b'\x89PNG\r\n\x1a\n':
            meta["format"] = "PNG"
        elif data[:6] in (b'GIF87a', b'GIF89a'):
            meta["format"] = "GIF"
        elif data[:2] == b'BM':
            meta["format"] = "BMP"
        else:
            meta["format"] = "Unknown"
            if b'<html' in data.lower()[:500] or b'<script' in data.lower()[:500]:
                meta["suspicious_indicators"].append("Fichier image contenant du HTML/JavaScript — possible polyglot")

        # Parse image dimensions
        try:
            if meta["format"] == "PNG" and len(data) > 24:
                import struct
                w = struct.unpack('>I', data[16:20])[0]
                h = struct.unpack('>I', data[20:24])[0]
                meta["dimensions"] = f"{w}x{h}"
            elif meta["format"] == "JPEG":
                # Simple SOF parser
                i = 2
                while i < len(data) - 9:
                    if data[i] == 0xFF and data[i+1] in (0xC0, 0xC2):
                        h = (data[i+5] << 8) + data[i+6]
                        w = (data[i+7] << 8) + data[i+8]
                        meta["dimensions"] = f"{w}x{h}"
                        break
                    elif data[i] == 0xFF:
                        seg_len = (data[i+2] << 8) + data[i+3]
                        i += 2 + seg_len
                    else:
                        i += 1
            elif meta["format"] == "GIF" and len(data) > 10:
                import struct
                w = struct.unpack('<H', data[6:8])[0]
                h = struct.unpack('<H', data[8:10])[0]
                meta["dimensions"] = f"{w}x{h}"
        except Exception:
            pass

        # Check for EXIF data (JPEG)
        if meta["format"] == "JPEG" and b'Exif' in data[:100]:
            meta["has_exif"] = True
            # Extract basic EXIF info
            exif_info = []
            # Look for common EXIF strings
            for marker in [b'Software', b'Creator', b'Author', b'Adobe', b'Photoshop',
                          b'GIMP', b'Paint', b'Snagit', b'Screenshot']:
                if marker in data:
                    exif_info.append(marker.decode('ascii', errors='ignore'))
            if exif_info:
                meta["exif_software"] = exif_info[:3]

        # Suspicious indicators
        if meta["size_bytes"] < 500:
            meta["suspicious_indicators"].append("Image tres petite — possible tracking pixel")
        if meta["format"] == "JPEG" and meta["dimensions"]:
            try:
                w, h = map(int, meta["dimensions"].split("x"))
                if w == 1 and h == 1:
                    meta["suspicious_indicators"].append("Image 1x1 — tracking pixel confirme")
                elif w > 2000 or h > 2000:
                    meta["suspicious_indicators"].append("Image haute resolution — contenu potentiellement dissimule")
            except Exception:
                pass

        # Check for embedded URLs in image data (steganography indicator)
        try:
            text_in_image = data.decode('ascii', errors='ignore')
            urls_in_img = URL_PATTERN.findall(text_in_image[100:])  # Skip header
            if urls_in_img:
                meta["suspicious_indicators"].append(f"URLs detectees dans les donnees binaires ({len(urls_in_img)})")
                meta["embedded_urls"] = urls_in_img[:5]
        except Exception:
            pass

        return meta if (meta["format"] or meta["suspicious_indicators"]) else None

    def _analyze_embedded_document(self, doc_bytes: bytes, mime_type: str, html_wrapper: str) -> dict:
        """Analyse forensique d'un document embarque (PDF, Office, etc.) dans une PJ HTML."""
        result = {
            "type": "unknown",
            "mime": mime_type,
            "size_bytes": len(doc_bytes),
            "is_fake_viewer": False,
            "viewer_title": "",
            "text_content": "",
            "urls": [],
            "phishing_urls": [],
            "images_count": 0,
            "pages": 0,
            "metadata": {},
            "phishing_indicators": [],
            "victim_targeting": {},
            "call_to_action": "",
            "producer": "",
        }

        # Detect fake viewer pattern from wrapper HTML
        wrapper_lower = html_wrapper.lower()
        viewer_titles = re.findall(r'<title[^>]*>([^<]+)</title>', html_wrapper, re.I)
        if viewer_titles:
            result["viewer_title"] = viewer_titles[0].strip()
        viewer_keywords = ['pdf viewer', 'document viewer', 'view document', 'secure document',
                           'file preview', 'preview', 'adobe', 'acrobat']
        if any(kw in wrapper_lower for kw in viewer_keywords):
            result["is_fake_viewer"] = True
            result["phishing_indicators"].append("Faux lecteur de documents — la PJ HTML simule un viewer PDF/document")
        if '<embed' in wrapper_lower and 'data:application/pdf' in wrapper_lower:
            result["is_fake_viewer"] = True
            result["phishing_indicators"].append("PDF embarque via data URI dans un tag <embed> — contourne les filtres email")

        # Analyze PDF content
        if doc_bytes[:5] == b'%PDF-' or 'pdf' in mime_type.lower():
            result["type"] = "pdf"
            try:
                import fitz  # PyMuPDF
                doc = fitz.open(stream=doc_bytes, filetype="pdf")
                result["pages"] = doc.page_count
                result["metadata"] = {k: v for k, v in (doc.metadata or {}).items() if v}
                result["producer"] = doc.metadata.get("producer", "") if doc.metadata else ""

                all_text = ""
                all_links = []
                total_images = 0

                for page in doc:
                    page_text = page.get_text()
                    all_text += page_text + "\n"
                    for link in page.get_links():
                        if link.get("uri"):
                            all_links.append(link["uri"])
                    total_images += len(page.get_images())

                result["text_content"] = all_text.strip()
                result["urls"] = list(set(all_links))
                result["images_count"] = total_images

                # Analyze PDF text for phishing patterns
                text_lower = all_text.lower()

                # Call to action detection
                cta_patterns = [
                    (r'click\s+(?:the\s+)?(?:button|here|link|below)\s+to\s+(?:view|open|access|download|verify|confirm)', 'en'),
                    (r'view\s+(?:now|document|file)', 'en'),
                    (r'open\s+(?:now|document|file)', 'en'),
                    (r'cliquez\s+(?:ici|sur le bouton)\s+pour', 'fr'),
                    (r'voir\s+(?:le\s+)?document', 'fr'),
                ]
                for pattern, lang in cta_patterns:
                    cta_match = re.search(pattern, text_lower)
                    if cta_match:
                        result["call_to_action"] = cta_match.group(0).strip()
                        result["phishing_indicators"].append(f"Call-to-action: \"{result['call_to_action']}\"")
                        break

                # "Securely sent" / document lure patterns
                lure_patterns = ['securely sent', 'encrypted document', 'secure document',
                                 'confidential', 'protected document', 'document securise',
                                 'this document is', 'vous avez recu']
                for lure in lure_patterns:
                    if lure in text_lower:
                        result["phishing_indicators"].append(f"Leurre de document securise: \"{lure}\"")
                        break

                # Victim email in PDF text
                recipient = self.report.get("metadata", {}).get("to", "")
                if recipient:
                    # Extract email from "Name <email>" format
                    email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', recipient)
                    if email_match:
                        victim_email = email_match.group(0).lower()
                        if victim_email in text_lower:
                            result["phishing_indicators"].append(f"Email de la victime integre dans le PDF: {victim_email}")
                            result["victim_targeting"]["email_in_pdf"] = True

                # Analyze each URL for phishing characteristics
                for url in all_links:
                    url_analysis = self._analyze_phishing_url(url)
                    if url_analysis["is_phishing"]:
                        result["phishing_urls"].append(url_analysis)

                doc.close()

            except ImportError:
                # PyMuPDF not installed — fallback to regex parsing
                result["metadata"]["note"] = "PyMuPDF non installe — analyse PDF limitee"
                pdf_text = doc_bytes.decode('latin-1', errors='ignore')

                # Extract URI actions from raw PDF
                uris = re.findall(r'/URI\s*\(([^)]+)\)', pdf_text)
                result["urls"] = list(set(uris))
                for url in uris:
                    url_analysis = self._analyze_phishing_url(url)
                    if url_analysis["is_phishing"]:
                        result["phishing_urls"].append(url_analysis)

                # Extract text from raw PDF (basic)
                text_parts = re.findall(r'\(([^)]{3,})\)', pdf_text)
                readable = [t for t in text_parts if re.search(r'[a-zA-Z]{3,}', t)]
                result["text_content"] = ' '.join(readable[:50])

                # Producer
                prod = re.search(r'/Producer\s*\(([^)]+)\)', pdf_text)
                if prod:
                    result["producer"] = prod.group(1)

            except Exception as e:
                result["metadata"]["error"] = str(e)[:100]

        return result

    def _analyze_phishing_url(self, url: str) -> dict:
        """Analyse forensique d'une URL pour detecter les indicateurs de phishing."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path

        analysis = {
            "url": url,
            "domain": domain,
            "is_phishing": False,
            "indicators": [],
            "risk_score": 0,
            "victim_name_in_url": None,
            "victim_domain_in_url": None,
        }

        # Random/generated subdomain detection
        subdomain = domain.split('.')[0] if '.' in domain else ''
        if len(subdomain) > 15 and re.match(r'^[a-z0-9]+$', subdomain):
            analysis["indicators"].append(f"Sous-domaine genere aleatoirement: {subdomain}")
            analysis["risk_score"] += 25

        # Root domain analysis — compromised legitimate site
        root_domain = '.'.join(domain.split('.')[-2:]) if domain.count('.') >= 1 else domain
        non_tech_domains = ['brewery', 'shop', 'store', 'restaurant', 'hotel', 'farm',
                           'salon', 'clinic', 'church', 'school', 'bakery', 'florist']
        if any(kw in root_domain for kw in non_tech_domains):
            analysis["indicators"].append(f"Domaine compromise (non-tech): {root_domain}")
            analysis["risk_score"] += 20

        # Path analysis — random segments
        segments = [s for s in path.split('/') if s]
        random_segs = [s for s in segments if len(s) > 10 and re.match(r'^[a-z0-9]+$', s)]
        if len(random_segs) >= 3:
            analysis["indicators"].append(f"{len(random_segs)}/{len(segments)} segments de chemin obfusques/aleatoires")
            analysis["risk_score"] += 15

        # Victim name in URL path
        name_matches = re.findall(r'[A-Z][a-z]+\.[A-Z][a-z]+', path)
        if name_matches:
            analysis["victim_name_in_url"] = name_matches[0]
            analysis["indicators"].append(f"Nom de la victime dans l'URL: {name_matches[0]}")
            analysis["risk_score"] += 20

        # Victim/target domain in URL path
        domain_in_path = re.findall(r'([a-z0-9-]+\.(?:com|fr|org|net|co\.uk|de|io))', path.lower())
        if domain_in_path:
            analysis["victim_domain_in_url"] = domain_in_path[0]
            analysis["indicators"].append(f"Domaine cible dans le chemin URL: {domain_in_path[0]}")
            analysis["risk_score"] += 20

        # Brand name embedded in random path (e.g., "k4ovwl1ep1p7amvmg0xmsc" contains "msc")
        brand_names = ['msc', 'dhl', 'microsoft', 'google', 'apple', 'paypal', 'amazon']
        for brand in brand_names:
            for seg in segments:
                if brand in seg.lower() and len(seg) > len(brand) + 5 and re.search(r'[0-9]', seg):
                    analysis["indicators"].append(f"Marque '{brand}' camuflee dans un segment aleatoire: {seg}")
                    analysis["risk_score"] += 10
                    break

        # Very long URL path (tracking/evasion)
        if len(path) > 100:
            analysis["indicators"].append(f"Chemin URL anormalement long ({len(path)} chars) — tracking ou evasion")
            analysis["risk_score"] += 5

        # Final determination
        if analysis["risk_score"] >= 30:
            analysis["is_phishing"] = True

        return analysis

    def _scan_attachment_content(self, data: bytes, iocs_out: dict):
        """Analyse approfondie du contenu d'une pièce jointe HTML."""
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            return

        lower_text = text.lower()

        # ── Extract URLs ──
        urls = list(set(URL_PATTERN.findall(text)))
        for url in urls:
            parsed = urlparse(url)
            iocs_out["urls"].append({
                "url": url,
                "domain": parsed.netloc,
                "scheme": parsed.scheme,
                "path": parsed.path,
                "suspicious_tld": any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS),
                "ip_based": bool(IP_PATTERN.match(parsed.netloc)),
                "url_shortener": self._is_url_shortener(parsed.netloc),
                "mismatched_display": False,
                "source": "attachment"
            })

        # ── Extract IPs ──
        ips = list(set(IP_PATTERN.findall(text)))
        for ip in ips:
            iocs_out["ips"].append({"ip": ip, "is_private": self._is_private_ip(ip), "source": "attachment"})

        # ── Detect embedded documents (data URI / Base64) ──
        import base64 as b64_module
        embedded_doc = None  # Will hold extracted PDF/doc analysis

        # Check for data URI embeds (fake PDF viewer, fake document viewer)
        data_uri_match = re.search(r'(?:src|data)\s*=\s*["\']data:([^;]+);base64,([^"\']+)["\']', text, re.I)
        if data_uri_match:
            embed_mime = data_uri_match.group(1)
            embed_b64 = data_uri_match.group(2)
            try:
                embed_bytes = b64_module.b64decode(embed_b64)
                embedded_doc = self._analyze_embedded_document(embed_bytes, embed_mime, text)
            except Exception as e:
                embedded_doc = {"type": "unknown", "error": str(e)[:100]}

        # ── Decode Base64 content to analyze hidden payload ──
        decoded_text = ""
        b64_matches = re.findall(r'[A-Za-z0-9+/=]{200,}', text)
        decoded_segments = []
        if b64_matches:
            for b64 in b64_matches:
                try:
                    decoded_bytes = b64_module.b64decode(b64)
                    # Check if it's a PDF or binary document
                    if decoded_bytes[:5] == b'%PDF-' and not embedded_doc:
                        embedded_doc = self._analyze_embedded_document(decoded_bytes, 'application/pdf', text)
                        continue
                    decoded = decoded_bytes.decode('utf-8', errors='ignore')
                    if len(decoded) > 50 and ('<' in decoded or 'http' in decoded.lower()):
                        decoded_segments.append(decoded)
                        decoded_text += decoded + "\n"
                except Exception:
                    pass

        # Combine original + decoded for analysis
        full_text = text + "\n" + decoded_text
        full_lower = full_text.lower()

        # ── Deep HTML Analysis ──
        analysis = {
            "has_forms": False,
            "form_targets": [],
            "has_password_field": False,
            "has_scripts": False,
            "script_techniques": [],
            "has_redirects": False,
            "redirect_targets": [],
            "has_iframes": False,
            "iframe_sources": [],
            "has_obfuscation": False,
            "obfuscation_methods": [],
            "has_data_exfil": False,
            "external_resources": [],
            "decoded_content_summary": "",
            "decoded_urls": [],
            "threat_type": "unknown",
            "threat_description": "",
            "file_size": len(data),
        }

        # Extract URLs from decoded content
        if decoded_text:
            decoded_urls = list(set(URL_PATTERN.findall(decoded_text)))
            analysis["decoded_urls"] = decoded_urls[:20]
            # Add decoded URLs to IOCs
            for url in decoded_urls:
                parsed = urlparse(url)
                if url not in [u["url"] for u in iocs_out["urls"]]:
                    iocs_out["urls"].append({
                        "url": url, "domain": parsed.netloc, "scheme": parsed.scheme,
                        "path": parsed.path,
                        "suspicious_tld": any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS),
                        "ip_based": bool(IP_PATTERN.match(parsed.netloc)),
                        "url_shortener": self._is_url_shortener(parsed.netloc),
                        "mismatched_display": False, "source": "attachment (decoded)"
                    })
            # Extract IPs from decoded content
            decoded_ips = list(set(IP_PATTERN.findall(decoded_text)))
            for ip in decoded_ips:
                if ip not in [i["ip"] for i in iocs_out["ips"]]:
                    iocs_out["ips"].append({"ip": ip, "is_private": self._is_private_ip(ip), "source": "attachment (decoded)"})

            # Summarize decoded content
            summary_parts = []
            if '<form' in decoded_text.lower():
                summary_parts.append("formulaire de connexion")
            if 'password' in decoded_text.lower():
                summary_parts.append("champ mot de passe")
            if '<script' in decoded_text.lower():
                summary_parts.append("scripts JavaScript")
            if decoded_urls:
                summary_parts.append(f"{len(decoded_urls)} URLs cachees")
            if '<img' in decoded_text.lower():
                summary_parts.append("images")
            if '<style' in decoded_text.lower() or 'css' in decoded_text.lower():
                summary_parts.append("styles CSS (imitation de page)")
            # Brand impersonation detection
            brands = ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint',
                       'google', 'gmail', 'apple', 'icloud', 'amazon', 'paypal',
                       'dhl', 'fedex', 'ups', 'maersk', 'msc', 'bank', 'netflix',
                       'facebook', 'instagram', 'linkedin', 'whatsapp', 'dropbox']
            found_brands = [b for b in brands if b in decoded_text.lower()]
            if found_brands:
                summary_parts.append(f"imitation de marque: {', '.join(found_brands[:3])}")
                analysis["brand_impersonation"] = found_brands[:5]
            analysis["decoded_content_summary"] = "; ".join(summary_parts) if summary_parts else "Contenu HTML decode"
            analysis["has_decoded_content"] = True
            analysis["decoded_size"] = len(decoded_text)

        # Forms — credential harvesting detection (search in full text including decoded)
        form_pattern = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', re.I)
        forms = form_pattern.findall(full_text)
        if forms or '<form' in full_lower:
            analysis["has_forms"] = True
            analysis["form_targets"] = [f for f in forms if f]

        # Password fields — confirms credential harvesting
        if re.search(r'type=["\']password["\']', full_lower) or re.search(r'type\s*=\s*["\']password', full_lower):
            analysis["has_password_field"] = True

        # Email/login fields
        has_email_field = bool(re.search(r'type=["\']email["\']', full_lower))
        has_login_keywords = any(kw in full_lower for kw in ['login', 'sign in', 'log in', 'connexion', 'mot de passe', 'identifiant', 'username', 'verify your', 'confirm your', 'update your'])

        # Scripts and obfuscation
        script_indicators = {
            'eval(': 'eval() — execution dynamique de code',
            'document.write(': 'document.write() — injection de contenu',
            'atob(': 'atob() — decodage Base64',
            'fromcharcode': 'String.fromCharCode() — construction caractere par caractere',
            'unescape(': 'unescape() — decodage URL encoding',
            'window.location': 'window.location — redirection JavaScript',
            'document.location': 'document.location — redirection JavaScript',
            'settimeout': 'setTimeout — execution differee',
            'setinterval': 'setInterval — execution repetee',
            'xmlhttprequest': 'XMLHttpRequest — requete HTTP sortante',
            'fetch(': 'fetch() — requete HTTP sortante',
            '.submit()': '.submit() — soumission automatique de formulaire',
            'navigator.sendbeacon': 'sendBeacon — exfiltration de donnees',
            'btoa(': 'btoa() — encodage Base64 sortant'
        }
        detected_scripts = []
        for indicator, desc in script_indicators.items():
            if indicator in full_lower:
                detected_scripts.append(desc)
        if detected_scripts:
            analysis["has_scripts"] = True
            analysis["script_techniques"] = detected_scripts

        # Obfuscation detection
        obf_methods = []
        if lower_text.count('\\x') > 10:
            obf_methods.append("Hex encoding (\\\\x)")
        if lower_text.count('\\u') > 10:
            obf_methods.append("Unicode encoding (\\\\u)")
        if 'charcodeat' in lower_text or 'fromcharcode' in lower_text:
            obf_methods.append("Character code manipulation")
        if re.search(r'var\s+\w+\s*=\s*\[.*\]\s*;\s*\w+\s*=\s*\w+\.join', lower_text):
            obf_methods.append("Array join obfuscation")
        if 'atob(' in lower_text:
            obf_methods.append("Base64 encoded payload")
        if b64_matches:
            total_b64 = sum(len(m) for m in b64_matches)
            obf_methods.append(f"Contenu encode en Base64 ({total_b64:,} caracteres, {len(b64_matches)} bloc(s))")
            if decoded_segments:
                obf_methods.append(f"Decode avec succes : {len(decoded_segments)} segment(s) contenant du HTML")
        if obf_methods:
            analysis["has_obfuscation"] = True
            analysis["obfuscation_methods"] = obf_methods

        # Redirects (in full text)
        meta_refresh = re.findall(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\';\s]+)', full_text, re.I)
        js_redirects = re.findall(r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)', full_text, re.I)
        all_redirects = meta_refresh + js_redirects
        if all_redirects:
            analysis["has_redirects"] = True
            analysis["redirect_targets"] = all_redirects[:5]

        # Iframes (in full text)
        iframe_srcs = re.findall(r'<iframe[^>]*src=["\']([^"\']+)["\']', full_text, re.I)
        if iframe_srcs or '<iframe' in full_lower:
            analysis["has_iframes"] = True
            analysis["iframe_sources"] = iframe_srcs[:5]

        # External resources (from full text)
        ext_resources = re.findall(r'(?:src|href)=["\']((https?://)[^"\']+)["\']', full_text, re.I)
        analysis["external_resources"] = list(set(r[0] for r in ext_resources))[:15]

        # Data exfiltration indicators
        if any(kw in full_lower for kw in ['sendbeacon', 'xmlhttprequest', 'fetch(', '.send(']):
            analysis["has_data_exfil"] = True

        # ── Determine threat type and build narrative ──
        if analysis["has_password_field"] or (analysis["has_forms"] and (has_email_field or has_login_keywords)):
            analysis["threat_type"] = "credential_harvesting"
            targets = ', '.join(analysis['form_targets'][:3]) if analysis['form_targets'] else 'inconnu'
            analysis["threat_description"] = (
                f"Credential harvesting — cette pièce jointe HTML contient un formulaire de connexion "
                f"avec champ mot de passe. Les identifiants saisis sont envoyés vers : {targets}. "
            )
            if analysis.get("brand_impersonation"):
                analysis["threat_description"] += f"Imitation de marque detectee : {', '.join(analysis['brand_impersonation'][:3])}. "
            if analysis["has_obfuscation"]:
                analysis["threat_description"] += f"Le code est obfusqué ({', '.join(analysis['obfuscation_methods'][:2])}). "
            if analysis["has_scripts"]:
                analysis["threat_description"] += f"Techniques JS : {', '.join(analysis['script_techniques'][:3])}."

        elif analysis["has_redirects"]:
            targets = ', '.join(analysis['redirect_targets'][:2])
            analysis["threat_type"] = "redirect_phishing"
            analysis["threat_description"] = (
                f"Redirection malveillante — ce fichier HTML redirige automatiquement vers : {targets}. "
                f"L'utilisateur est amené sur un site externe contrôlé par l'attaquant."
            )
            if analysis.get("brand_impersonation"):
                analysis["threat_description"] += f" Imitation de marque : {', '.join(analysis['brand_impersonation'][:3])}."

        elif analysis["has_scripts"] and analysis["has_obfuscation"]:
            analysis["threat_type"] = "obfuscated_payload"
            desc = (
                f"Payload obfusqué — ce fichier HTML ({analysis['file_size']:,} octets) contient du code obfusqué "
                f"({', '.join(analysis['obfuscation_methods'][:3])}). "
            )
            if analysis["script_techniques"]:
                desc += f"Techniques : {', '.join(analysis['script_techniques'][:3])}. "
            if analysis.get("decoded_content_summary"):
                desc += f"Contenu decode : {analysis['decoded_content_summary']}. "
            if analysis.get("brand_impersonation"):
                desc += f"Imitation de marque : {', '.join(analysis['brand_impersonation'][:3])}. "
            desc += "Objectif probable : credential harvesting ou redirection vers site malveillant."
            analysis["threat_description"] = desc

        elif analysis["has_obfuscation"] and decoded_segments:
            analysis["threat_type"] = "obfuscated_payload"
            desc = (
                f"Payload obfusqué — ce fichier HTML ({analysis['file_size']:,} octets) contient du contenu "
                f"masqué en Base64. "
            )
            if analysis.get("decoded_content_summary"):
                desc += f"Apres decodage : {analysis['decoded_content_summary']}. "
            if analysis.get("decoded_urls"):
                desc += f"{len(analysis['decoded_urls'])} URL(s) cachee(s) dans le payload. "
            if analysis.get("brand_impersonation"):
                desc += f"Imitation de marque : {', '.join(analysis['brand_impersonation'][:3])}. "
            desc += "Technique classique de phishing pour contourner les filtres email."
            analysis["threat_description"] = desc

        elif analysis["has_forms"]:
            analysis["threat_type"] = "data_collection"
            analysis["threat_description"] = (
                f"Collecte de données — ce fichier HTML contient un formulaire "
                f"qui envoie les données vers : {', '.join(analysis['form_targets'][:3]) or 'inconnu'}."
            )

        elif analysis["has_iframes"]:
            analysis["threat_type"] = "iframe_injection"
            analysis["threat_description"] = (
                f"Injection iframe — ce fichier charge du contenu externe via iframe : "
                f"{', '.join(analysis['iframe_sources'][:2]) or 'source masquée'}."
            )

        elif analysis["has_obfuscation"]:
            analysis["threat_type"] = "suspicious_html"
            desc = (
                f"Fichier HTML suspect ({analysis['file_size']:,} octets) contenant du contenu obfusqué "
                f"({', '.join(analysis['obfuscation_methods'][:3])}). "
            )
            if analysis.get("decoded_content_summary"):
                desc += f"Contenu decode : {analysis['decoded_content_summary']}. "
            desc += "Vecteur courant de phishing — analyse manuelle recommandée."
            analysis["threat_description"] = desc

        else:
            analysis["threat_type"] = "suspicious_html"
            analysis["threat_description"] = f"Fichier HTML en pièce jointe ({analysis['file_size']:,} octets) — vecteur courant de phishing."

        # ── Integrate embedded document analysis ──
        if embedded_doc:
            analysis["embedded_document"] = embedded_doc

            # Add embedded doc URLs to IOCs
            for url in embedded_doc.get("urls", []):
                parsed = urlparse(url)
                if url not in [u["url"] for u in iocs_out["urls"]]:
                    iocs_out["urls"].append({
                        "url": url, "domain": parsed.netloc, "scheme": parsed.scheme,
                        "path": parsed.path,
                        "suspicious_tld": any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS),
                        "ip_based": bool(IP_PATTERN.match(parsed.netloc)),
                        "url_shortener": self._is_url_shortener(parsed.netloc),
                        "mismatched_display": False, "source": f"embedded_{embedded_doc['type']}"
                    })

            # Override threat type and description if embedded doc has strong signals
            if embedded_doc.get("phishing_urls") or embedded_doc.get("phishing_indicators"):
                phish_urls = embedded_doc.get("phishing_urls", [])
                indicators = embedded_doc.get("phishing_indicators", [])

                if embedded_doc.get("is_fake_viewer"):
                    analysis["threat_type"] = "fake_document_viewer"
                    desc = f"Faux lecteur de documents — "
                    if embedded_doc.get("viewer_title"):
                        desc += f"titre \"{embedded_doc['viewer_title']}\". "
                    desc += f"Le fichier HTML embarque un {embedded_doc['type'].upper()} de {embedded_doc['size_bytes']:,} octets "
                    desc += f"encode en Base64 via data URI. "

                    if embedded_doc.get("text_content"):
                        # Summarize PDF text
                        pdf_text = embedded_doc["text_content"][:200].replace('\n', ' ').strip()
                        desc += f"Contenu du PDF : \"{pdf_text}\". "

                    if phish_urls:
                        pu = phish_urls[0]
                        desc += f"URL de phishing detectee : {pu['domain']} "
                        if pu.get("victim_name_in_url"):
                            desc += f"(nom de la victime \"{pu['victim_name_in_url']}\" integre dans l'URL). "
                        if pu.get("victim_domain_in_url"):
                            desc += f"Domaine cible \"{pu['victim_domain_in_url']}\" dans le chemin. "
                        desc += f"Score de risque URL : {pu['risk_score']}/100. "
                        desc += f"Indicateurs : {'; '.join(pu['indicators'][:4])}. "

                    if embedded_doc.get("producer"):
                        desc += f"Generateur PDF : {embedded_doc['producer']}. "

                    if embedded_doc.get("call_to_action"):
                        desc += f"Appel a l'action : \"{embedded_doc['call_to_action']}\". "

                    desc += "Technique avancee : le PDF est invisible aux filtres email car encode en Base64 dans le HTML."
                    analysis["threat_description"] = desc

                    # Update brand detection from embedded doc
                    victim_target = embedded_doc.get("victim_targeting", {})
                    analysis["victim_targeting"] = victim_target
                    analysis["embedded_phishing_urls"] = phish_urls

        iocs_out["scripts_detected"] = analysis["has_scripts"]
        iocs_out["html_analysis"] = analysis

    # ── URL Sandboxing ──

    def _sandbox_urls(self):
        """Capture d'ecran des URLs suspectes via navigateur headless."""
        try:
            from scripts.url_sandbox import sandbox_urls, is_available
        except ImportError:
            try:
                from url_sandbox import sandbox_urls, is_available
            except ImportError:
                return

        if not is_available():
            self.report["url_sandbox"] = {"available": False, "results": []}
            return

        urls = self.report.get("iocs", {}).get("urls", [])
        if not urls:
            self.report["url_sandbox"] = {"available": True, "results": []}
            return

        print(f"[SANDBOX] Lancement du sandboxing pour {len(urls)} URL(s)...")
        results = sandbox_urls(urls, max_urls=5)
        self.report["url_sandbox"] = {
            "available": True,
            "results": results,
            "total_captured": len([r for r in results if r.get("screenshot_b64")]),
        }
        print(f"[SANDBOX] {len(results)} URL(s) capturee(s)")

    # ── Whois du domaine expediteur ──

    @staticmethod
    def _extract_root_domain(domain: str) -> str:
        """Extrait le domaine racine enregistrable (ex: sub.firebaseapp.com → firebaseapp.com)."""
        # Liste des suffixes multi-niveaux connus (PaaS, hosting, etc.)
        multi_suffixes = [
            '.co.uk', '.co.jp', '.co.kr', '.co.in', '.co.za', '.co.nz',
            '.com.au', '.com.br', '.com.cn', '.com.mx', '.com.ar',
            '.org.uk', '.net.au', '.ac.uk', '.gov.uk',
            '.firebaseapp.com', '.web.app', '.herokuapp.com',
            '.azurewebsites.net', '.cloudfront.net', '.amazonaws.com',
            '.pages.dev', '.netlify.app', '.vercel.app', '.onrender.com',
            '.appspot.com', '.blogspot.com', '.github.io', '.gitlab.io',
        ]
        domain_lower = domain.lower()
        for suffix in multi_suffixes:
            if domain_lower.endswith(suffix):
                # Pour les PaaS (firebaseapp.com, herokuapp.com), query le domaine parent
                base = suffix.lstrip('.')
                return base

        # Sinon extraire les 2 derniers segments (example.com)
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain

    def _whois_from_domain(self):
        """Recherche les informations Whois du domaine From."""
        from_addr = self.report.get("metadata", {}).get("from", "")
        match = re.search(r'@([\w\.-]+)', from_addr)
        if not match:
            return
        full_domain = match.group(1).lower()
        root_domain = self._extract_root_domain(full_domain)

        whois_info = {
            "domain": full_domain,
            "root_domain": root_domain,
            "is_subdomain": full_domain != root_domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "country": None,
            "org": None,
            "domain_age_days": None,
            "suspicious_age": False,
            "hosting_platform": None,
            "error": None
        }

        # Détecter les plateformes d'hébergement (indicateur de phishing)
        hosting_platforms = {
            'firebaseapp.com': 'Google Firebase', 'web.app': 'Google Firebase',
            'herokuapp.com': 'Heroku', 'azurewebsites.net': 'Microsoft Azure',
            'netlify.app': 'Netlify', 'vercel.app': 'Vercel',
            'pages.dev': 'Cloudflare Pages', 'onrender.com': 'Render',
            'appspot.com': 'Google App Engine', 'blogspot.com': 'Blogger',
            'github.io': 'GitHub Pages', 'gitlab.io': 'GitLab Pages',
        }
        for suffix, platform in hosting_platforms.items():
            if full_domain.endswith(suffix):
                whois_info["hosting_platform"] = platform
                break

        try:
            import whois
            print(f"[WHOIS] Query: {root_domain}" + (f" (sous-domaine de {full_domain})" if full_domain != root_domain else ""))
            w = whois.whois(root_domain)

            if w.registrar:
                whois_info["registrar"] = str(w.registrar)
            if w.creation_date:
                cd = w.creation_date if not isinstance(w.creation_date, list) else w.creation_date[0]
                if cd:
                    whois_info["creation_date"] = cd.strftime("%Y-%m-%d") if hasattr(cd, 'strftime') else str(cd)
                    try:
                        from datetime import datetime
                        age = (datetime.now() - cd).days
                        whois_info["domain_age_days"] = age
                        if age < 90:
                            whois_info["suspicious_age"] = True
                    except Exception:
                        pass
            if w.expiration_date:
                ed = w.expiration_date if not isinstance(w.expiration_date, list) else w.expiration_date[0]
                if ed and hasattr(ed, 'strftime'):
                    whois_info["expiration_date"] = ed.strftime("%Y-%m-%d")
            if w.updated_date:
                ud = w.updated_date if not isinstance(w.updated_date, list) else w.updated_date[0]
                if ud and hasattr(ud, 'strftime'):
                    whois_info["updated_date"] = ud.strftime("%Y-%m-%d")
            if w.name_servers:
                ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                whois_info["name_servers"] = [str(n).lower() for n in ns[:4]]
            if w.country:
                whois_info["country"] = str(w.country)
            if w.org:
                whois_info["org"] = str(w.org)

            print(f"[WHOIS] {root_domain} — registrar: {whois_info['registrar']}, age: {whois_info['domain_age_days']}j")
        except ImportError:
            whois_info["error"] = "Module python-whois non installe"
            print("[WHOIS] Module python-whois non disponible — pip install python-whois")
        except Exception as e:
            whois_info["error"] = str(e)
            print(f"[WHOIS] Erreur pour {root_domain}: {e}")

        self.report["whois"] = whois_info

    # ── Analyse d'impact — Scenario victime + MITRE ATT&CK ──

    def _generate_impact_analysis(self):
        """Genere un scenario d'attaque complet: point de vue victime + mapping MITRE ATT&CK."""
        iocs = self.report.get("iocs", {})
        attachments = self.report.get("attachments", [])
        auth = self.report.get("authentication", {})
        metadata = self.report.get("metadata", {})
        sandbox = self.report.get("url_sandbox", {})

        # Detect attack characteristics
        has_credential_harvest = False
        has_malware = False
        has_redirect = False
        has_brand_spoof = False
        has_obfuscation = False
        has_exfiltration = False
        brands_found = []
        threat_types = []
        decoded_urls = []

        for att in attachments:
            content_analysis = att.get("content_analysis", {})
            tt = content_analysis.get("threat_type", "")
            if tt:
                threat_types.append(tt)
            if tt == "credential_harvesting":
                has_credential_harvest = True
            if tt in ("redirect_phishing",):
                has_redirect = True
            if content_analysis.get("has_obfuscation"):
                has_obfuscation = True
            if content_analysis.get("has_exfiltration"):
                has_exfiltration = True
            bp = content_analysis.get("brand_impersonation", [])
            if bp:
                has_brand_spoof = True
                brands_found.extend(bp)
            decoded_urls.extend(content_analysis.get("decoded_urls", []))
            if att.get("suspicious_extension"):
                # HTML/HTM/SVG = phishing page, not malware
                fname = att.get("filename", "").lower()
                if not fname.endswith(('.html', '.htm', '.svg', '.shtml')):
                    has_malware = True

        suspicious_ext = [a for a in attachments if a.get("suspicious_extension")]
        html_att = [a for a in attachments if a.get("content_type", "").startswith("text/html") or
                    a.get("filename", "").lower().endswith(('.html', '.htm', '.svg'))]

        urls = iocs.get("urls", [])
        suspicious_urls = [u for u in urls if u.get("suspicious_tld") or u.get("ip_based") or u.get("url_shortener")]
        keywords = iocs.get("keywords", [])

        # Also check iocs-level html_attachment_analysis
        html_analysis = iocs.get("html_attachment_analysis", {})
        embedded = html_analysis.get("embedded_document", {})
        if html_analysis.get("brand_impersonation"):
            has_brand_spoof = True
            brands_found.extend(html_analysis["brand_impersonation"])
        if html_analysis.get("has_obfuscation"):
            has_obfuscation = True
        if html_analysis.get("has_data_exfil"):
            has_exfiltration = True
        if html_analysis.get("has_forms") and html_analysis.get("has_password_field"):
            has_credential_harvest = True
        if html_analysis.get("threat_type"):
            threat_types.append(html_analysis["threat_type"])
        decoded_urls.extend(html_analysis.get("decoded_urls", []))
        # Embedded document phishing URLs
        if embedded.get("phishing_urls"):
            for pu in embedded["phishing_urls"]:
                decoded_urls.append(pu["url"])
        has_fake_viewer = embedded.get("is_fake_viewer", False)
        embedded_pdf_text = embedded.get("text_content", "")
        embedded_cta = embedded.get("call_to_action", "")

        brands_found = list(set(brands_found))

        # ── Build victim scenario (step by step) ──
        steps = []
        impact = []
        mitre = []

        # Step 1: Email reception
        sender = metadata.get("from", "inconnu")
        subject = metadata.get("subject", "")
        step1 = f"La victime recoit un email de '{sender}'"
        if subject:
            step1 += f" avec l'objet '{subject}'"
        if has_brand_spoof:
            step1 += f". L'email imite la marque {', '.join(brands_found[:2]).upper()} pour paraitre legitime"
        if auth.get("spf", {}).get("status") in ("fail", "softfail", "absent"):
            step1 += ". L'authentification SPF echoue — l'expediteur est probablement usurpe"
        steps.append({"step": 1, "action": "Reception", "description": step1, "icon": "envelope"})

        # MITRE: Initial Access
        mitre.append({
            "tactic": "Initial Access",
            "technique": "T1566.001 — Spearphishing Attachment" if attachments else "T1566.002 — Spearphishing Link",
            "description": "Email de phishing avec piece jointe HTML malveillante" if html_att else "Email contenant des liens vers des pages de phishing"
        })

        # Step 2: User opens attachment or clicks link
        if html_att:
            att_name = html_att[0].get("filename", "piece_jointe.html")
            step2 = f"La victime ouvre la piece jointe '{att_name}'"
            if has_fake_viewer:
                viewer_title = embedded.get("viewer_title", "PDF Viewer")
                step2 += f". Le navigateur affiche un faux lecteur de documents intitule \"{viewer_title}\""
                step2 += f". En realite, le HTML embarque un PDF de {embedded.get('size_bytes', 0):,} octets encode en Base64"
            elif has_obfuscation:
                step2 += ". Le fichier HTML contient du code obfusque en Base64 qui se decode automatiquement dans le navigateur"
            else:
                step2 += ". Le fichier s'ouvre dans le navigateur par defaut"
            steps.append({"step": 2, "action": "Ouverture PJ", "description": step2, "icon": "file-code"})

            mitre.append({
                "tactic": "Execution",
                "technique": "T1204.002 — User Execution: Malicious File",
                "description": f"Ouverture du fichier HTML '{att_name}' qui execute du code cote client"
            })
            if has_fake_viewer:
                mitre.append({
                    "tactic": "Defense Evasion",
                    "technique": "T1027.006 — HTML Smuggling",
                    "description": "PDF embarque dans un fichier HTML via data URI Base64 — contourne les filtres email et les passerelles de securite"
                })
        elif suspicious_urls or urls:
            target_url = suspicious_urls[0]["url"] if suspicious_urls else urls[0].get("url", "")
            step2 = f"La victime clique sur le lien dans l'email"
            if has_redirect:
                step2 += f". Le lien redirige vers une page controlee par l'attaquant"
            steps.append({"step": 2, "action": "Clic sur lien", "description": step2, "icon": "link"})

        # Step 3: What the victim sees
        if has_fake_viewer and embedded.get("phishing_urls"):
            pu = embedded["phishing_urls"][0]
            step3 = f"Le PDF affiche un message personalise — "
            if embedded_pdf_text:
                # Clean up for display
                clean_text = embedded_pdf_text.replace('\n', ' ').strip()[:150]
                step3 += f"\"{clean_text}\". "
            if embedded_cta:
                step3 += f"Un bouton \"{embedded_cta.upper()}\" invite a cliquer. "
            step3 += f"Le lien mene vers {pu['domain']}"
            if pu.get("victim_name_in_url"):
                step3 += f" — l'URL contient le nom de la victime ({pu['victim_name_in_url']}) et son domaine ({pu.get('victim_domain_in_url','')}) pour personnaliser l'attaque"
            steps.append({"step": 3, "action": "Faux document PDF", "description": step3, "icon": "browser"})

            mitre.append({
                "tactic": "Collection",
                "technique": "T1598.003 — Phishing for Information: Spearphishing Link",
                "description": f"Lien de phishing personalise avec le nom et le domaine de la victime dans l'URL"
            })
        elif has_credential_harvest:
            step3 = "Une page de connexion apparait"
            if has_brand_spoof:
                step3 += f", imitant parfaitement {brands_found[0].upper()}"
                step3 += ". Le design, les logos et les couleurs sont copies pour tromper la victime"
            step3 += ". Un formulaire demande l'identifiant et le mot de passe"
            steps.append({"step": 3, "action": "Page de phishing", "description": step3, "icon": "browser"})

            mitre.append({
                "tactic": "Collection",
                "technique": "T1056.003 — Input Capture: Web Portal Capture",
                "description": "Formulaire web frauduleux capturant les identifiants de la victime"
            })
        elif has_redirect and decoded_urls:
            step3 = f"Le navigateur est redirige a travers {len(decoded_urls)} URL(s) intermediaires"
            step3 += " pour echapper aux filtres de securite, avant d'atteindre la page finale de l'attaquant"
            steps.append({"step": 3, "action": "Redirections", "description": step3, "icon": "shuffle"})
        elif has_obfuscation and has_brand_spoof:
            step3 = "Le code Base64 se decode automatiquement et affiche une page imitant " + ', '.join(b.upper() for b in brands_found[:2])
            step3 += ". La victime voit une interface apparemment legitime (logo, couleurs, mise en page copiee)"
            steps.append({"step": 3, "action": "Page frauduleuse", "description": step3, "icon": "browser"})

            mitre.append({
                "tactic": "Defense Evasion",
                "technique": "T1027 — Obfuscated Files or Information",
                "description": "Contenu HTML encode en Base64 pour echapper aux filtres email et antivirus"
            })
        elif has_malware:
            step3 = "Un telechargement se lance automatiquement ou la victime est invitee a ouvrir un fichier executable"
            steps.append({"step": 3, "action": "Telechargement", "description": step3, "icon": "download"})

        # Step 4: Data exfiltration / credential theft
        if has_fake_viewer and embedded.get("phishing_urls"):
            pu = embedded["phishing_urls"][0]
            step4 = "La victime clique sur le bouton et atterrit sur une page de phishing externe"
            step4 += f" hebergee sur {pu['domain']}"
            if pu.get("indicators"):
                step4 += f". Indicateurs suspects : {'; '.join(pu['indicators'][:3])}"
            step4 += ". La page demande probablement des identifiants de connexion ou redirige vers un payload malveillant"
            steps.append({"step": 4, "action": "Page de phishing externe", "description": step4, "icon": "key"})

            mitre.append({
                "tactic": "Credential Access",
                "technique": "T1556 — Modify Authentication Process",
                "description": f"Page de phishing sur domaine compromis ({pu['domain']}) collectant les identifiants"
            })
        elif has_credential_harvest:
            step4 = "La victime entre ses identifiants. Les donnees sont envoyees en temps reel au serveur de l'attaquant"
            if has_exfiltration:
                step4 += " via une requete AJAX/fetch vers un domaine externe"
            if decoded_urls:
                ext_domains = list(set(urlparse(u).netloc for u in decoded_urls if urlparse(u).netloc))[:3]
                if ext_domains:
                    step4 += f". Domaines de collecte identifies : {', '.join(ext_domains)}"
            steps.append({"step": 4, "action": "Vol d'identifiants", "description": step4, "icon": "key"})

            mitre.append({
                "tactic": "Exfiltration",
                "technique": "T1041 — Exfiltration Over C2 Channel",
                "description": "Identifiants transmis au serveur de l'attaquant via HTTP/HTTPS"
            })
        elif has_obfuscation and has_brand_spoof:
            step4 = "La page frauduleuse invite la victime a saisir ses identifiants ou informations personnelles"
            step4 += f" sur un formulaire imitant {brands_found[0].upper()}"
            step4 += ". Les donnees saisies sont envoyees directement au serveur de l'attaquant"
            steps.append({"step": 4, "action": "Collecte de donnees", "description": step4, "icon": "key"})

            mitre.append({
                "tactic": "Collection",
                "technique": "T1056.003 — Input Capture: Web Portal Capture",
                "description": "Page web frauduleuse capturant les informations saisies par la victime"
            })
        elif has_malware:
            step4 = "Le malware s'installe sur le poste de la victime, potentiellement avec persistence et acces a distance"
            steps.append({"step": 4, "action": "Installation malware", "description": step4, "icon": "bug"})
            mitre.append({
                "tactic": "Persistence",
                "technique": "T1547 — Boot or Logon Autostart Execution",
                "description": "Le malware s'installe pour persister apres redemarrage"
            })

        # Step 5: Post-compromise consequences (skip if already handled by fake_viewer)
        if has_fake_viewer and embedded.get("phishing_urls"):
            pass  # Already handled above
        elif has_credential_harvest:
            step5 = "Avec les identifiants voles, l'attaquant peut : "
            consequences = []
            if any(b in ['microsoft', 'office 365', 'outlook', 'o365'] for b in [x.lower() for x in brands_found]):
                consequences.extend([
                    "acceder a la boite mail et lire les emails confidentiels",
                    "envoyer des emails de phishing internes (compromission en chaine)",
                    "acceder a OneDrive/SharePoint et voler des documents sensibles",
                    "modifier les regles de transfert pour surveiller les communications"
                ])
            elif any(b in ['google', 'gmail'] for b in [x.lower() for x in brands_found]):
                consequences.extend([
                    "acceder a Gmail, Google Drive, et tous les services Google associes",
                    "lire les emails et telecharger les fichiers partages",
                    "utiliser le compte pour des campagnes de phishing ulterieures"
                ])
            elif any(b in ['dhl', 'msc', 'maersk', 'fedex', 'ups'] for b in [x.lower() for x in brands_found]):
                consequences.extend([
                    "acceder au portail logistique et modifier les expeditions",
                    "voler les informations de tracking et contacts commerciaux",
                    "compromettre la chaine d'approvisionnement"
                ])
            else:
                consequences.extend([
                    "acceder au compte compromis et aux donnees associees",
                    "lancer des attaques de phishing internes (lateral phishing)",
                    "voler des donnees sensibles ou financieres"
                ])
            step5 += "; ".join(consequences)
            steps.append({"step": 5, "action": "Consequences", "description": step5, "icon": "alert-triangle"})

            mitre.append({
                "tactic": "Impact",
                "technique": "T1078 — Valid Accounts",
                "description": "Utilisation des identifiants voles pour acceder aux systemes internes"
            })
            mitre.append({
                "tactic": "Lateral Movement",
                "technique": "T1534 — Internal Spearphishing",
                "description": "Envoi d'emails de phishing depuis le compte compromis vers d'autres employes"
            })

            impact = [
                {"category": "Confidentialite", "level": "CRITIQUE", "detail": "Acces complet aux emails et documents de la victime"},
                {"category": "Integrite", "level": "ELEVE", "detail": "L'attaquant peut envoyer des emails au nom de la victime"},
                {"category": "Disponibilite", "level": "MOYEN", "detail": "Verrouillage potentiel du compte si l'attaquant change le mot de passe"},
                {"category": "Financier", "level": "ELEVE", "detail": "Risque de fraude (BEC), modification de coordonnees bancaires"},
                {"category": "Reputationnel", "level": "ELEVE", "detail": "Compromission en chaine via phishing interne"}
            ]
        elif has_obfuscation and has_brand_spoof:
            step5 = "Avec les donnees volees, l'attaquant peut : "
            consequences = []
            if any(b in ['dhl', 'msc', 'maersk', 'fedex', 'ups'] for b in [x.lower() for x in brands_found]):
                consequences.extend([
                    "acceder aux portails logistiques et detourner des expeditions",
                    "voler des informations commerciales et contacts clients",
                    "lancer des fraudes BEC (Business Email Compromise) sur la chaine d'approvisionnement",
                    "utiliser les identifiants pour compromettre d'autres comptes (reutilisation de mots de passe)"
                ])
            else:
                consequences.extend([
                    "acceder au compte compromis et aux donnees associees",
                    "lancer des attaques de phishing internes",
                    "voler des donnees sensibles ou financieres"
                ])
            step5 += "; ".join(consequences)
            steps.append({"step": 5, "action": "Consequences", "description": step5, "icon": "alert-triangle"})

            mitre.append({
                "tactic": "Impact",
                "technique": "T1078 — Valid Accounts",
                "description": "Utilisation des identifiants voles pour acceder aux systemes de la victime"
            })

            impact = [
                {"category": "Confidentialite", "level": "CRITIQUE", "detail": "Vol d'identifiants et acces aux comptes de la victime"},
                {"category": "Integrite", "level": "ELEVE", "detail": "L'attaquant peut agir au nom de la victime"},
                {"category": "Disponibilite", "level": "MOYEN", "detail": "Verrouillage potentiel des comptes compromis"},
                {"category": "Financier", "level": "ELEVE", "detail": "Fraude BEC, detournement de transactions commerciales"},
                {"category": "Reputationnel", "level": "ELEVE", "detail": "Compromission en chaine via le compte vole"}
            ]
        elif has_malware:
            step5 = "Le malware permet a l'attaquant de : controler le poste a distance, voler des fichiers, capturer les frappes clavier, se propager sur le reseau interne"
            steps.append({"step": 5, "action": "Consequences", "description": step5, "icon": "alert-triangle"})
            impact = [
                {"category": "Confidentialite", "level": "CRITIQUE", "detail": "Acces total aux fichiers et donnees du poste"},
                {"category": "Integrite", "level": "CRITIQUE", "detail": "Modification/destruction de donnees possibles"},
                {"category": "Disponibilite", "level": "ELEVE", "detail": "Ransomware possible — chiffrement des fichiers"},
                {"category": "Financier", "level": "CRITIQUE", "detail": "Cout de remediation, potentielle rancon"},
            ]
        else:
            # Generic scenario
            if steps and len(steps) < 5:
                step5 = "L'attaquant collecte des informations sur la victime ou l'organisation pour preparer des attaques ulterieures plus ciblees"
                steps.append({"step": len(steps) + 1, "action": "Reconnaissance", "description": step5, "icon": "eye"})

        # Step 5 for fake viewer
        if has_fake_viewer and embedded.get("phishing_urls") and not has_credential_harvest:
            pu = embedded["phishing_urls"][0]
            step5 = "Avec les identifiants voles, l'attaquant peut : "
            consequences = []
            if any(b in ['dhl', 'msc', 'maersk', 'fedex', 'ups'] for b in [x.lower() for x in brands_found]):
                consequences.extend([
                    "acceder aux portails logistiques et detourner des expeditions",
                    "voler des informations commerciales et contacts clients",
                    "lancer des fraudes BEC (Business Email Compromise) sur la chaine d'approvisionnement",
                    "utiliser les identifiants pour compromettre d'autres comptes (reutilisation de mots de passe)"
                ])
            else:
                consequences.extend([
                    "acceder au compte compromis et aux donnees associees",
                    "lancer des attaques de phishing internes (lateral phishing)",
                    "voler des donnees sensibles ou financieres"
                ])
            step5 += "; ".join(consequences)
            steps.append({"step": 5, "action": "Consequences", "description": step5, "icon": "alert-triangle"})

            mitre.append({
                "tactic": "Impact",
                "technique": "T1078 — Valid Accounts",
                "description": "Utilisation des identifiants voles pour acceder aux systemes de la victime"
            })

            impact = [
                {"category": "Confidentialite", "level": "CRITIQUE", "detail": "Vol d'identifiants et acces aux comptes de la victime"},
                {"category": "Integrite", "level": "ELEVE", "detail": "L'attaquant peut agir au nom de la victime"},
                {"category": "Disponibilite", "level": "MOYEN", "detail": "Verrouillage potentiel des comptes compromis"},
                {"category": "Financier", "level": "ELEVE", "detail": "Fraude BEC, detournement de transactions commerciales"},
                {"category": "Reputationnel", "level": "ELEVE", "detail": "Compromission en chaine via le compte vole"}
            ]

        # Determine primary attack classification
        if has_fake_viewer:
            attack_class = "HTML Smuggling — Faux Lecteur PDF avec Lien de Phishing Personalise"
        elif has_credential_harvest and has_brand_spoof:
            attack_class = "Credential Harvesting avec Brand Impersonation"
        elif has_credential_harvest:
            attack_class = "Credential Harvesting"
        elif has_malware:
            attack_class = "Malware Delivery"
        elif has_redirect:
            attack_class = "Redirect Phishing"
        elif has_obfuscation and has_brand_spoof:
            attack_class = "Phishing Obfusque avec Imitation de Marque"
        elif has_obfuscation:
            attack_class = "Obfuscated Payload"
        elif has_brand_spoof:
            attack_class = "Brand Impersonation"
        else:
            attack_class = "Phishing Generique"

        # Immediate response actions
        response_actions = [
            "Isoler l'email et empecher d'autres utilisateurs de l'ouvrir",
            "Bloquer les IOCs identifies (domaines, IPs, hashes) au niveau du proxy et du pare-feu",
            "Verifier dans les logs si des utilisateurs ont clique ou soumis des identifiants",
        ]
        if has_credential_harvest:
            response_actions.extend([
                "Forcer la reinitialisation du mot de passe pour tout utilisateur ayant soumis ses identifiants",
                "Verifier les regles de transfert email et les sessions actives sur les comptes potentiellement compromis",
                "Activer/verifier le MFA sur tous les comptes concernes"
            ])
        if has_obfuscation and has_brand_spoof and not has_credential_harvest:
            response_actions.extend([
                "Analyser la piece jointe HTML dans une sandbox pour identifier la page de phishing",
                "Forcer la reinitialisation des mots de passe si un utilisateur a ouvert la PJ",
                "Signaler la page de phishing aux marques imitees (" + ', '.join(b.upper() for b in brands_found[:3]) + ")"
            ])
        if has_malware:
            response_actions.extend([
                "Isoler le poste du reseau immediatement",
                "Lancer un scan antivirus complet et verifier les processus en cours",
                "Analyser le fichier dans une sandbox (ex: Any.Run, VirusTotal)"
            ])
        response_actions.append("Documenter l'incident et notifier l'equipe SOC")

        self.report["impact_analysis"] = {
            "attack_classification": attack_class,
            "victim_scenario": steps,
            "mitre_attack": mitre,
            "business_impact": impact,
            "response_actions": response_actions,
            "brands_targeted": brands_found,
            "threat_types_detected": list(set(threat_types)),
        }

    # ── Scoring de risque ──

    def _calculate_risk_score(self):
        """Calcule un score de risque phishing (0-100)."""
        score = 0
        factors = []

        # Authentication failures (+30 max)
        auth = self.report["authentication"]
        if auth["spf"]["status"] in ("fail", "softfail"):
            score += 15
            factors.append(f"SPF {auth['spf']['status']} (+15)")
        elif auth["spf"]["status"] in ("none", "permerror", "temperror"):
            score += 10
            factors.append(f"SPF {auth['spf']['status']} — expéditeur non vérifié (+10)")
        elif auth["spf"]["status"] == "absent":
            score += 5
            factors.append("SPF absent (+5)")

        if auth["dkim"]["status"] == "fail":
            score += 15
            factors.append("DKIM fail (+15)")
        elif auth["dkim"]["status"] in ("none", "permerror", "temperror"):
            score += 10
            factors.append(f"DKIM {auth['dkim']['status']} — message non signé (+10)")
        elif auth["dkim"]["status"] == "absent":
            score += 5
            factors.append("DKIM absent (+5)")

        if auth["dmarc"]["status"] == "fail":
            score += 10
            factors.append("DMARC fail (+10)")
        elif auth["dmarc"]["status"] in ("permerror", "temperror", "none"):
            score += 8
            factors.append(f"DMARC {auth['dmarc']['status']} — politique non appliquée (+8)")

        # Header anomalies (+15 max)
        anomalies = self.report["headers_analysis"].get("anomalies", [])
        for a in anomalies:
            if "Return-Path" in a:
                score += 10
                factors.append(f"Anomalie header: {a} (+10)")
            elif "Reply-To" in a:
                score += 8
                factors.append(f"Anomalie header: {a} (+8)")
            elif "gratuit" in a or "free" in a.lower():
                score += 5
                factors.append(f"Anomalie header: {a} (+5)")

        # Suspicious URLs (+20 max)
        iocs = self.report["iocs"]
        suspicious_urls = iocs.get("suspicious_urls_count", 0)
        if suspicious_urls > 0:
            url_score = min(suspicious_urls * 7, 20)
            score += url_score
            factors.append(f"{suspicious_urls} URL(s) suspecte(s) (+{url_score})")

        # Mismatched links (très suspect)
        mismatched = sum(1 for u in iocs.get("urls", []) if u.get("mismatched_display"))
        if mismatched > 0:
            score += 15
            factors.append(f"{mismatched} lien(s) avec texte trompeur (+15)")

        # Phishing keywords (+15 max)
        kw_count = iocs.get("keywords_count", 0)
        if kw_count > 0:
            kw_score = min(kw_count * 3, 15)
            score += kw_score
            factors.append(f"{kw_count} mot(s)-clé(s) phishing (+{kw_score})")

        # Suspicious attachments (+15 max)
        suspicious_att = sum(1 for a in self.report["attachments"] if a.get("suspicious_extension"))
        if suspicious_att > 0:
            att_score = min(suspicious_att * 10, 15)
            score += att_score
            factors.append(f"{suspicious_att} pièce(s) jointe(s) suspecte(s) (+{att_score})")

        # Scripts detected in HTML attachments (+15)
        if iocs.get("attachment_scripts_detected"):
            score += 15
            factors.append("Scripts detectes dans PJ HTML (+15)")

        # URLs found in attachments (+10)
        att_urls = iocs.get("attachment_urls_count", 0)
        if att_urls > 0:
            att_url_score = min(att_urls * 5, 10)
            score += att_url_score
            factors.append(f"{att_urls} URL(s) dans pièce(s) jointe(s) (+{att_url_score})")

        # HTML attachment deep analysis scoring
        html_analysis = iocs.get("html_attachment_analysis", {})
        if html_analysis.get("has_obfuscation"):
            score += 20
            factors.append("Contenu obfusque (Base64) dans PJ HTML (+20)")
        if html_analysis.get("brand_impersonation"):
            brands = html_analysis["brand_impersonation"]
            score += 15
            factors.append(f"Imitation de marque : {', '.join(brands[:3]).upper()} (+15)")
        if html_analysis.get("has_decoded_content"):
            score += 10
            factors.append("Contenu cache decode depuis Base64 (+10)")
        if html_analysis.get("has_data_exfil"):
            score += 15
            factors.append("Exfiltration de donnees detectee (+15)")
        embedded = html_analysis.get("embedded_document", {})
        if embedded.get("is_fake_viewer"):
            score += 20
            factors.append(f"Faux lecteur de documents ({embedded.get('type','').upper()}) (+20)")
        if embedded.get("phishing_urls"):
            score += 20
            pu = embedded["phishing_urls"][0]
            factors.append(f"URL de phishing dans {embedded.get('type','doc').upper()}: {pu['domain']} (+20)")
            if pu.get("victim_name_in_url"):
                score += 10
                factors.append(f"Nom de la victime dans l'URL: {pu['victim_name_in_url']} (+10)")
            if pu.get("victim_domain_in_url"):
                score += 5
                factors.append(f"Domaine cible dans l'URL: {pu['victim_domain_in_url']} (+5)")
        if embedded.get("call_to_action"):
            score += 5
            factors.append(f"Call-to-action dans PDF: \"{embedded['call_to_action']}\" (+5)")
        if html_analysis.get("has_iframes"):
            score += 10
            factors.append("Iframes detectes dans PJ HTML (+10)")
        if html_analysis.get("has_password_field"):
            score += 20
            factors.append("Champ mot de passe dans PJ HTML (+20)")
        elif html_analysis.get("has_forms"):
            score += 10
            factors.append("Formulaire dans PJ HTML (+10)")

        # ── Body HTML analysis (emails without HTML attachment) ──
        # If no HTML attachment analysis, analyze the body HTML directly
        if not html_analysis:
            body_html = self._get_body_html()
            if body_html:
                body_lower = body_html.lower()
                body_analysis = {}

                # Brand impersonation in body
                brands_map = {
                    'microsoft': 'Microsoft', 'office365': 'Office365', 'outlook': 'Outlook',
                    'onedrive': 'OneDrive', 'sharepoint': 'SharePoint', 'google': 'Google',
                    'gmail': 'Gmail', 'apple': 'Apple', 'icloud': 'iCloud', 'amazon': 'Amazon',
                    'paypal': 'PayPal', 'dhl': 'DHL', 'fedex': 'FedEx', 'ups': 'UPS',
                    'maersk': 'Maersk', 'msc': 'MSC', 'netflix': 'Netflix',
                    'facebook': 'Facebook', 'instagram': 'Instagram', 'linkedin': 'LinkedIn',
                    'whatsapp': 'WhatsApp', 'dropbox': 'Dropbox', 'docusign': 'DocuSign',
                    'adobe': 'Adobe', 'wells fargo': 'Wells Fargo', 'chase': 'Chase',
                    'bank of america': 'Bank of America', 'citi': 'Citi',
                }
                # Also check Subject for brand impersonation
                subject = str(self.report.get("metadata", {}).get("subject", "")).lower()
                from_name = str(self.report.get("metadata", {}).get("from", "")).lower()
                check_text = body_lower + " " + subject + " " + from_name
                found_brands = [display for key, display in brands_map.items() if key in check_text]
                if found_brands:
                    score += 15
                    factors.append(f"Imitation de marque (body/subject): {', '.join(found_brands[:3])} (+15)")
                    body_analysis["brand_impersonation"] = found_brands[:5]

                # Password field in body
                if re.search(r'type=["\']password["\']', body_lower):
                    score += 20
                    factors.append("Champ mot de passe dans le body HTML (+20)")

                # Forms in body
                elif '<form' in body_lower:
                    score += 10
                    factors.append("Formulaire dans le body HTML (+10)")

                # Obfuscation in body (large Base64 blobs, hex encoding)
                b64_in_body = re.findall(r'[A-Za-z0-9+/=]{200,}', body_html)
                if b64_in_body:
                    score += 15
                    factors.append(f"Contenu obfusqué Base64 dans le body ({len(b64_in_body)} bloc(s)) (+15)")
                elif body_lower.count('\\x') > 10 or body_lower.count('\\u') > 10:
                    score += 10
                    factors.append("Obfuscation hex/unicode dans le body (+10)")

                # Scripts in body
                script_keywords = ['eval(', 'document.write(', 'atob(', 'fromcharcode', 'unescape(']
                if any(kw in body_lower for kw in script_keywords):
                    score += 10
                    factors.append("Scripts suspects dans le body HTML (+10)")

                self.report["iocs"]["body_html_analysis"] = body_analysis

        # ── Suspicious From domain (brand camouflage) ──
        from_addr = self.report.get("headers_analysis", {}).get("from_address", "")
        from_domain = from_addr.split("@")[-1].lower() if from_addr and "@" in from_addr else ""
        if from_domain and from_domain not in FREE_EMAIL_PROVIDERS:
            # Check if domain mimics a well-known brand
            brand_keywords = ['microsoft', 'google', 'apple', 'amazon', 'paypal', 'dhl',
                              'fedex', 'netflix', 'facebook', 'instagram', 'linkedin',
                              'outlook', 'office', 'security', 'account', 'verify',
                              'support', 'service', 'admin', 'help', 'login', 'secure',
                              'update', 'alert', 'notification', 'info', 'access']
            domain_no_tld = from_domain.split('.')[0] if '.' in from_domain else from_domain
            matching_brand_kw = [kw for kw in brand_keywords if kw in domain_no_tld]
            if matching_brand_kw and from_domain not in ['microsoft.com', 'google.com', 'apple.com',
                'amazon.com', 'paypal.com', 'dhl.com', 'fedex.com', 'netflix.com', 'facebook.com',
                'instagram.com', 'linkedin.com', 'outlook.com', 'office.com', 'office365.com']:
                score += 10
                factors.append(f"Domaine expéditeur suspect: {from_domain} (contient: {', '.join(matching_brand_kw[:3])}) (+10)")

        # ── Reply-To free email with corporate From ──
        reply_to = self.report.get("headers_analysis", {}).get("reply_to_address", "")
        if reply_to and from_addr:
            reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if reply_domain in FREE_EMAIL_PROVIDERS and from_domain not in FREE_EMAIL_PROVIDERS:
                score += 10
                factors.append(f"Reply-To email gratuit ({reply_domain}) alors que From est corporate ({from_domain}) (+10)")

        # ── Priority/Importance header abuse ──
        importance = str(self.msg.get("Importance", "")).lower() if self.msg else ""
        x_priority = str(self.msg.get("X-Priority", "")) if self.msg else ""
        if importance == "high" or x_priority in ("1", "2"):
            score += 5
            factors.append(f"Email marqué haute priorité (Importance: {importance or 'high'}, X-Priority: {x_priority or 'N/A'}) (+5)")

        # Threat Intel API enrichment scoring
        for ip_e in iocs.get("ip_enrichment", []):
            abuse = ip_e.get("abuse", {})
            if abuse.get("abuse_score", 0) >= 75:
                score += 15
                factors.append(f"IP {ip_e['ip']} — AbuseIPDB score {abuse['abuse_score']}% (+15)")
            elif abuse.get("abuse_score", 0) >= 25:
                score += 8
                factors.append(f"IP {ip_e['ip']} — AbuseIPDB score {abuse['abuse_score']}% (+8)")
            if abuse.get("is_tor"):
                score += 10
                factors.append(f"IP {ip_e['ip']} — Noeud Tor (+10)")
            vt = ip_e.get("vt", {})
            if vt.get("malicious", 0) >= 3:
                score += 15
                factors.append(f"IP {ip_e['ip']} — VirusTotal {vt['malicious']} detections (+15)")

        for url_e in iocs.get("url_enrichment", []):
            if url_e.get("urlhaus", {}).get("listed"):
                score += 20
                factors.append(f"URL listee dans URLhaus (+20)")
            vt = url_e.get("vt", {})
            if vt.get("malicious", 0) >= 3:
                score += 15
                factors.append(f"URL — VirusTotal {vt['malicious']} detections (+15)")

        for h_e in iocs.get("hash_enrichment", []):
            vt = h_e.get("vt", {})
            if vt.get("malicious", 0) >= 1:
                score += 20
                factors.append(f"Hash PJ {h_e.get('filename','')} — VirusTotal {vt['malicious']} detections (+20)")
            if h_e.get("urlhaus", {}).get("listed"):
                score += 15
                factors.append(f"Hash PJ listee dans URLhaus (+15)")

        # Cap at 100
        score = min(score, 100)

        # Verdict
        if score >= 70:
            level = "CRITICAL"
            verdict = "Très probablement du phishing — investigation immédiate recommandée"
        elif score >= 45:
            level = "HIGH"
            verdict = "Indicateurs de phishing forts — analyse approfondie requise"
        elif score >= 25:
            level = "MEDIUM"
            verdict = "Éléments suspects détectés — vérification manuelle conseillée"
        elif score >= 10:
            level = "LOW"
            verdict = "Quelques éléments inhabituels — probablement légitime"
        else:
            level = "INFO"
            verdict = "Aucun indicateur de phishing significatif détecté"

        self.report["risk_scoring"] = {
            "score": score,
            "max_score": 100,
            "factors": factors
        }
        self.report["verdict"] = {
            "risk_level": level,
            "score": score,
            "summary": verdict,
            "recommendation": self._get_recommendation(level)
        }

    def _get_recommendation(self, level: str) -> str:
        """Retourne la recommandation selon le niveau de risque."""
        recommendations = {
            "CRITICAL": (
                "1. Ne pas cliquer sur les liens ni ouvrir les pièces jointes\n"
                "2. Isoler l'email et le transmettre à l'équipe SOC\n"
                "3. Vérifier si d'autres utilisateurs ont reçu le même email\n"
                "4. Bloquer les IOCs identifiés (domaines, IPs, URLs)\n"
                "5. Documenter l'incident dans le système de ticketing"
            ),
            "HIGH": (
                "1. Ne pas interagir avec l'email\n"
                "2. Escalader à l'équipe sécurité pour analyse approfondie\n"
                "3. Rechercher des emails similaires dans l'organisation\n"
                "4. Envisager le blocage préventif des IOCs"
            ),
            "MEDIUM": (
                "1. Vérifier manuellement l'authenticité de l'expéditeur\n"
                "2. Contacter l'expéditeur présumé par un canal alternatif\n"
                "3. Ne pas cliquer sur les liens avant vérification"
            ),
            "LOW": (
                "1. Rester vigilant mais aucune action immédiate requise\n"
                "2. Signaler en cas de doute persistant"
            ),
            "INFO": "Aucune action requise."
        }
        return recommendations.get(level, "Aucune action requise.")

    # ── Helpers ──

    def _extract_email_address(self, header_value: str) -> str:
        """Extrait l'adresse email pure d'un header."""
        match = re.search(r'<([^>]+)>', header_value)
        if match:
            return match.group(1)
        match = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', header_value)
        if match:
            return match.group(0)
        return header_value.strip()

    def _get_body_text(self) -> str:
        """Extrait le corps texte de l'email."""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            return payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            return payload.decode('utf-8', errors='replace')
        else:
            payload = self.msg.get_payload(decode=True)
            if payload:
                charset = self.msg.get_content_charset() or 'utf-8'
                try:
                    return payload.decode(charset, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    return payload.decode('utf-8', errors='replace')
        return ""

    def _get_body_html(self) -> str:
        """Extrait le corps HTML de l'email."""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            return payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            return payload.decode('utf-8', errors='replace')
        elif self.msg.get_content_type() == "text/html":
            # Non-multipart HTML email (body IS the HTML)
            payload = self.msg.get_payload(decode=True)
            if payload:
                charset = self.msg.get_content_charset() or 'utf-8'
                try:
                    return payload.decode(charset, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    return payload.decode('utf-8', errors='replace')
        return ""

    def _is_url_shortener(self, domain: str) -> bool:
        """Vérifie si le domaine est un raccourcisseur d'URL."""
        shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
            "tiny.cc", "rb.gy", "bl.ink", "lnkd.in"
        ]
        return domain.lower() in shorteners

    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée (RFC 1918)."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b = int(parts[0]), int(parts[1])
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 127:
                return True
        except ValueError:
            pass
        return False

    def _is_suspicious_extension(self, filename: str) -> bool:
        """Vérifie si l'extension du fichier est suspecte."""
        suspicious = [
            ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".wsf", ".msi", ".dll", ".com", ".pif", ".hta", ".cpl",
            ".jar", ".iso", ".img", ".lnk", ".docm", ".xlsm",
            ".pptm", ".dotm", ".xltm", ".ppam", ".sldm",
            ".html", ".htm", ".svg", ".xll", ".iqy"
        ]
        name_lower = filename.lower()
        return any(name_lower.endswith(ext) for ext in suspicious)


# ──────────────────────────────────────────────
# Point d'entrée CLI
# ──────────────────────────────────────────────

def analyze_single(eml_path: str, enable_ai=False) -> dict:
    """Analyse un seul fichier .eml."""
    analyzer = PhishingAnalyzer(eml_path)
    return analyzer.analyze(enable_ai=enable_ai)


def main():
    if len(sys.argv) < 2:
        print("Usage: python phishing_analyzer.py <fichier.eml | dossier> [--ai]")
        print("       python phishing_analyzer.py --demo [--ai]")
        sys.exit(1)

    # Parser les arguments
    args = sys.argv[1:]
    enable_ai = "--ai" in args
    args = [a for a in args if a != "--ai"]
    target = args[0] if args else "--demo"

    if target == "--demo":
        create_demo_email()
        target = "demo_phishing.eml"

    if enable_ai:
        print("[AI] Mode analyse IA activé")

    results = []

    if os.path.isdir(target):
        eml_files = [f for f in os.listdir(target) if f.endswith('.eml')]
        if not eml_files:
            print(f"[INFO] Aucun fichier .eml trouvé dans {target}")
            sys.exit(0)
        print(f"[INFO] {len(eml_files)} fichier(s) .eml trouvé(s)")
        for eml_file in sorted(eml_files):
            path = os.path.join(target, eml_file)
            print(f"\n{'='*60}")
            print(f"[ANALYSE] {eml_file}")
            print(f"{'='*60}")
            result = analyze_single(path, enable_ai=enable_ai)
            results.append(result)
            _print_summary(result)
    else:
        result = analyze_single(target, enable_ai=enable_ai)
        results.append(result)
        _print_summary(result)

    # Sauvegarder le rapport JSON
    output_file = "phishing_report.json"
    report_data = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "total_emails_analyzed": len(results),
        "analyses": results
    }
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Rapport JSON sauvegardé : {output_file}")

    return report_data


def _print_summary(result: dict):
    """Affiche un résumé lisible en console."""
    if "error" in result:
        print(f"  ERREUR: {result['error']}")
        return

    meta = result["metadata"]
    verdict = result["verdict"]
    iocs = result["iocs"]
    auth = result["authentication"]

    print(f"\n  De:      {meta['from']}")
    print(f"  À:       {meta['to']}")
    print(f"  Sujet:   {meta['subject']}")
    print(f"  Date:    {meta['date']}")
    print(f"\n  ── Authentification ──")
    print(f"  SPF:     {auth['spf']['status']}")
    print(f"  DKIM:    {auth['dkim']['status']}")
    print(f"  DMARC:   {auth['dmarc']['status']}")
    print(f"\n  ── IOCs ──")
    print(f"  URLs:    {iocs['urls_count']} (dont {iocs['suspicious_urls_count']} suspecte(s))")
    print(f"  IPs:     {iocs['ips_count']}")
    print(f"  Mots-clés phishing: {iocs['keywords_count']}")
    print(f"  Pièces jointes: {len(result['attachments'])}")
    print(f"\n  ── VERDICT ──")
    print(f"  Score:   {verdict['score']}/100")
    print(f"  Niveau:  {verdict['risk_level']}")
    print(f"  Résumé:  {verdict['summary']}")

    # Show AI results if available
    ai = result.get("ai_analysis")
    if ai and "error" not in ai:
        print("")
        print("  -- ANALYSE IA --")
        sem = ai.get("semantic_analysis", {})
        if sem:
            print("  Pretexte:    " + str(sem.get("pretext", "N/A")))
            print("  Emotion ciblee: " + str(sem.get("target_emotion", "N/A")))
            print("  Credibilite: " + str(sem.get("credibility_assessment", "N/A")) + "/10")
        soph = ai.get("sophistication", {})
        if soph:
            print("  Sophistication: " + str(soph.get("level", "N/A")) + " (" + str(soph.get("score", "N/A")) + "/10)")
            print("  Profil attaquant: " + str(soph.get("likely_threat_actor_profile", "N/A")))
        targeting = ai.get("targeting", {})
        if targeting:
            print("  Ciblage: " + str(targeting.get("type", "N/A")) + " (confiance: " + str(targeting.get("confidence", "N/A")) + ")")
        tactics = ai.get("social_engineering_tactics", [])
        if tactics:
            print("")
            print("  Tactiques SE detectees (" + str(len(tactics)) + "):")
            for t in tactics[:4]:
                print("    - " + str(t.get("tactic", "?")) + " [" + str(t.get("effectiveness", "?")) + "] -- " + str(t.get("cialdini_principle", "")))
        summary = ai.get("executive_summary", "")
        if summary:
            print("")
            print("  Resume executif:")
            print("  " + summary)
        provider = ai.get("_meta", {}).get("provider", "unknown")
        print("")
        print("  [Analyse par: " + provider + "]")


def create_demo_email():
    lines = []
    lines.append('From: "Service Securite" <security-alert@update-secure-login.tk>')
    lines.append('To: victim@example.com')
    lines.append('Subject: [URGENT] Votre compte a ete compromis - Action immediate requise')
    lines.append('Date: Thu, 26 Jun 2026 10:30:00 +0000')
    lines.append('Message-ID: <fake123@update-secure-login.tk>')
    lines.append('Reply-To: no-reply@totallylegit.xyz')
    lines.append('Return-Path: <bouncer@different-domain.ml>')
    lines.append('MIME-Version: 1.0')
    lines.append('Content-Type: multipart/mixed; boundary="boundary123"')
    lines.append('Authentication-Results: mx.example.com;')
    lines.append('    spf=fail smtp.mailfrom=update-secure-login.tk;')
    lines.append('    dkim=fail header.d=update-secure-login.tk;')
    lines.append('    dmarc=fail header.from=update-secure-login.tk')
    lines.append('Received: from [185.234.72.11] by mx.example.com')
    lines.append('')
    lines.append('--boundary123')
    lines.append('Content-Type: text/html; charset="utf-8"')
    lines.append('')
    lines.append('<html><body>')
    lines.append('<p>Cher utilisateur,</p>')
    lines.append('<p>Nous avons detecte une <b>activite inhabituelle</b> sur votre compte.</p>')
    lines.append('<p>Votre mot de passe a expire et votre compte sera <b>suspendu</b> dans 24h.</p>')
    lines.append('<p><b>Verifiez immediatement</b> votre identite en cliquant ci-dessous :</p>')
    lines.append('<p><a href="http://185.234.72.11/phishing/steal.php">https://www.banque-securisee.com/verification</a></p>')
    lines.append('<p>Vous pouvez aussi visiter : http://bit.ly/3xF4k3Link</p>')
    lines.append('<p>Agissez maintenant pour eviter la desactivation de votre compte.</p>')
    lines.append('<p>Cordialement,<br>Le Service Securite</p>')
    lines.append('</body></html>')
    lines.append('')
    lines.append('--boundary123')
    lines.append('Content-Type: application/x-msdownload; name="update_securite.exe"')
    lines.append('Content-Disposition: attachment; filename="update_securite.exe"')
    lines.append('Content-Transfer-Encoding: base64')
    lines.append('')
    lines.append('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==')
    lines.append('')
    lines.append('--boundary123--')
    demo = "\n".join(lines) + "\n"
    with open("demo_phishing.eml", "w", encoding="utf-8") as f:
        f.write(demo)
    print("[INFO] Email de demonstration cree : demo_phishing.eml")


if __name__ == "__main__":
    main()
