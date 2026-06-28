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
        """Charge et parse le fichier .eml."""
        try:
            with open(self.eml_path, 'rb') as f:
                self.msg = BytesParser(policy=policy.default).parse(f)
            return True
        except Exception as e:
            print(f"[ERREUR] Impossible de charger {self.eml_path}: {e}")
            return False

    def analyze(self, enable_ai=False) -> dict:
        """Lance l'analyse complète."""
        if not self.load_email():
            return {"error": f"Échec du chargement de {self.eml_path}"}

        self._extract_metadata()
        self._analyze_headers()
        self._check_authentication()
        self._extract_iocs()
        self._analyze_attachments()
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
            dmarc_match = re.search(r'dmarc=(pass|fail|none|bestguesspass)', auth_results, re.I)
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
        """Extrait tous les indicateurs de compromission."""
        body_text = self._get_body_text()
        body_html = self._get_body_html()
        full_content = body_text + " " + body_html

        # URLs
        urls = list(set(URL_PATTERN.findall(full_content)))
        url_analysis = []
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
                "mismatched_display": False  # Set during HTML analysis
            }
            url_analysis.append(url_info)

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

        # IPs
        ips = list(set(IP_PATTERN.findall(full_content)))
        # Filtrer les IPs privées pour les noter
        ip_analysis = []
        for ip in ips:
            ip_analysis.append({
                "ip": ip,
                "is_private": self._is_private_ip(ip)
            })

        # Domaines (extraits des URLs + du contenu)
        domains = list(set(DOMAIN_PATTERN.findall(full_content)))
        # Filtrer les domaines courants/bruit
        domains = [d for d in domains if len(d) > 4 and "." in d]

        self.report["iocs"] = {
            "urls": url_analysis,
            "urls_count": len(url_analysis),
            "ips": ip_analysis,
            "ips_count": len(ip_analysis),
            "domains": domains[:50],  # Limiter
            "domains_count": len(domains),
            "suspicious_urls_count": sum(
                1 for u in url_analysis
                if u["suspicious_tld"] or u["ip_based"] or u["url_shortener"] or u["mismatched_display"]
            )
        }

        # Analyse des mots-clés phishing
        keywords_found = []
        lower_content = full_content.lower()
        for kw in PHISHING_KEYWORDS:
            if kw.lower() in lower_content:
                keywords_found.append(kw)

        self.report["iocs"]["phishing_keywords"] = keywords_found
        self.report["iocs"]["keywords_count"] = len(keywords_found)

    # ── Pièces jointes ──

    def _analyze_attachments(self):
        """Analyse les pièces jointes."""
        attachments = []

        if self.msg.is_multipart():
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
                        attachments.append(att)

        self.report["attachments"] = attachments

    # ── Scoring de risque ──

    def _calculate_risk_score(self):
        """Calcule un score de risque phishing (0-100)."""
        score = 0
        factors = []

        # Authentication failures (+20 max)
        auth = self.report["authentication"]
        if auth["spf"]["status"] in ("fail", "softfail"):
            score += 15
            factors.append("SPF fail/softfail (+15)")
        elif auth["spf"]["status"] == "absent":
            score += 5
            factors.append("SPF absent (+5)")

        if auth["dkim"]["status"] == "fail":
            score += 15
            factors.append("DKIM fail (+15)")
        elif auth["dkim"]["status"] == "absent":
            score += 5
            factors.append("DKIM absent (+5)")

        if auth["dmarc"]["status"] == "fail":
            score += 10
            factors.append("DMARC fail (+10)")

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
            ".pptm", ".dotm", ".xltm", ".ppam", ".sldm"
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
