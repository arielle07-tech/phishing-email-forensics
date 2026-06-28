"""Tests unitaires pour le module d'analyse phishing."""

import json
import os
import sys
import tempfile

import pytest

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.phishing_analyzer import PhishingAnalyzer, create_demo_email


@pytest.fixture
def demo_eml_path():
    """Crée un email de demo et retourne son chemin."""
    original_dir = os.getcwd()
    tmp_dir = tempfile.mkdtemp()
    os.chdir(tmp_dir)
    create_demo_email()
    path = os.path.join(tmp_dir, "demo_phishing.eml")
    yield path
    os.chdir(original_dir)
    if os.path.exists(path):
        os.unlink(path)
    os.rmdir(tmp_dir)


@pytest.fixture
def analyzer(demo_eml_path):
    """Retourne un analyseur initialisé avec l'email demo."""
    return PhishingAnalyzer(demo_eml_path)


@pytest.fixture
def report(analyzer):
    """Retourne le rapport d'analyse complet."""
    return analyzer.analyze(enable_ai=False)


class TestPhishingAnalyzer:
    """Tests pour PhishingAnalyzer."""

    def test_load_email(self, analyzer):
        """L'email demo doit se charger sans erreur."""
        assert analyzer.load_email() is True

    def test_analyze_returns_dict(self, report):
        """analyze() doit retourner un dictionnaire."""
        assert isinstance(report, dict)
        assert "error" not in report

    def test_metadata_extraction(self, report):
        """Les métadonnées doivent être extraites correctement."""
        meta = report["metadata"]
        assert "security-alert@update-secure-login.tk" in meta["from"]
        assert meta["to"] == "victim@example.com"
        assert "[URGENT]" in meta["subject"]

    def test_authentication_spf_fail(self, report):
        """SPF doit être en échec pour l'email demo."""
        auth = report["authentication"]
        assert auth["spf"]["status"] == "fail"

    def test_authentication_dkim_fail(self, report):
        """DKIM doit être en échec."""
        assert report["authentication"]["dkim"]["status"] == "fail"

    def test_authentication_dmarc_fail(self, report):
        """DMARC doit être en échec."""
        assert report["authentication"]["dmarc"]["status"] == "fail"

    def test_iocs_urls_detected(self, report):
        """Des URLs doivent être détectées."""
        iocs = report["iocs"]
        assert iocs["urls_count"] >= 2
        assert iocs["suspicious_urls_count"] >= 1

    def test_iocs_ip_detected(self, report):
        """L'IP 185.234.72.11 doit être détectée."""
        ips = [ip["ip"] for ip in report["iocs"].get("ips", [])]
        assert "185.234.72.11" in ips

    def test_iocs_phishing_keywords(self, report):
        """Des mots-clés phishing doivent être détectés."""
        assert report["iocs"]["keywords_count"] >= 3

    def test_suspicious_attachment(self, report):
        """La pièce jointe .exe doit être détectée comme suspecte."""
        atts = report["attachments"]
        assert len(atts) >= 1
        exe_att = [a for a in atts if a["filename"] == "update_securite.exe"]
        assert len(exe_att) == 1
        assert exe_att[0]["suspicious_extension"] is True

    def test_attachment_hashes(self, report):
        """Les pièces jointes doivent avoir des hashes MD5 et SHA256."""
        for att in report["attachments"]:
            assert att.get("md5")
            assert att.get("sha256")
            assert len(att["md5"]) == 32
            assert len(att["sha256"]) == 64

    def test_risk_score_high(self, report):
        """Le score de risque doit être élevé (>= 80)."""
        score = report["verdict"]["score"]
        assert score >= 80, f"Score trop bas: {score}"

    def test_risk_level_critical(self, report):
        """Le niveau de risque doit être CRITICAL ou HIGH."""
        level = report["verdict"]["risk_level"]
        assert level in ("CRITICAL", "HIGH"), f"Niveau inattendu: {level}"

    def test_verdict_has_summary(self, report):
        """Le verdict doit contenir un résumé."""
        assert report["verdict"].get("summary")
        assert len(report["verdict"]["summary"]) > 10

    def test_header_anomalies(self, report):
        """Des anomalies de headers doivent être détectées."""
        anomalies = report["headers_analysis"].get("anomalies", [])
        assert len(anomalies) >= 1, "Aucune anomalie détectée"

    def test_risk_factors_present(self, report):
        """Des facteurs de risque doivent être listés."""
        factors = report["risk_scoring"].get("factors", [])
        assert len(factors) >= 5, f"Seulement {len(factors)} facteurs"


class TestEdgeCases:
    """Tests pour les cas limites."""

    def test_nonexistent_file(self):
        """Un fichier inexistant doit retourner une erreur."""
        analyzer = PhishingAnalyzer("/tmp/does_not_exist.eml")
        result = analyzer.analyze()
        assert "error" in result or not analyzer.load_email()

    def test_empty_eml(self):
        """Un fichier .eml vide doit être géré sans crash."""
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write("")
            path = f.name
        try:
            analyzer = PhishingAnalyzer(path)
            result = analyzer.analyze()
            assert isinstance(result, dict)
        finally:
            os.unlink(path)

    def test_minimal_eml(self):
        """Un email minimal (juste headers) doit être analysé."""
        content = "From: test@example.com\nTo: user@example.com\nSubject: Hello\n\nBody text."
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write(content)
            path = f.name
        try:
            analyzer = PhishingAnalyzer(path)
            result = analyzer.analyze()
            assert isinstance(result, dict)
            assert result["metadata"]["from"] == "test@example.com"
            assert result["verdict"]["score"] < 50, "Email légitime ne devrait pas être CRITICAL"
        finally:
            os.unlink(path)

    def test_report_json_serializable(self, report):
        """Le rapport doit être sérialisable en JSON."""
        json_str = json.dumps(report, ensure_ascii=False)
        assert len(json_str) > 100
        parsed = json.loads(json_str)
        assert parsed["verdict"]["score"] == report["verdict"]["score"]
