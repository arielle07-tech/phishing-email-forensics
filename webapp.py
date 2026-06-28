#!/usr/bin/env python3
"""
Phishing Email Forensics — Web Application
=============================================
Serveur Flask qui sert le dashboard et expose une API
pour analyser des fichiers .eml directement depuis l'interface.

Usage:
    python webapp.py                     # Lance sur http://0.0.0.0:8080
    python webapp.py --port 5000         # Port personnalisé
    python webapp.py --demo              # Pré-charge l'analyse demo
"""

import argparse
import json
import os
import sys
import tempfile
import traceback

from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS

# Ajouter le répertoire du projet au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.phishing_analyzer import PhishingAnalyzer, create_demo_email

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


@app.route("/")
def index():
    """Sert le dashboard HTML."""
    return send_from_directory(".", "dashboard.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_email():
    """
    Analyse un fichier .eml uploadé.
    Accepte: multipart/form-data avec champ 'file' (.eml)
    Retourne: JSON du rapport d'analyse
    """
    use_ai = request.form.get("ai", "true").lower() in ("true", "1", "yes", "oui")

    # Déterminer la source : fichier uploadé ou texte collé
    file = request.files.get("file")
    raw_text = request.form.get("text", "").strip()

    if not file and not raw_text:
        return jsonify({"error": "Aucune donnée fournie. Envoyez un fichier ou du texte brut."}), 400

    try:
        if raw_text:
            # Texte brut collé — créer un .eml temporaire
            with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, dir=REPORTS_DIR, mode="w", encoding="utf-8") as tmp:
                tmp.write(raw_text)
                tmp_path = tmp.name
            filename = "pasted_email"
        else:
            if not file.filename:
                return jsonify({"error": "Nom de fichier vide."}), 400
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in (".eml", ".txt", ".msg"):
                return jsonify({"error": f"Format '{ext}' non supporté. Formats acceptés : .eml, .txt, .msg"}), 400
            # Sauvegarder le fichier temporairement (toujours en .eml pour le parser)
            with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, dir=REPORTS_DIR) as tmp:
                file.save(tmp)
                tmp_path = tmp.name
            filename = os.path.splitext(file.filename)[0]

        # Lancer l'analyse
        analyzer = PhishingAnalyzer(tmp_path)
        result = analyzer.analyze(enable_ai=use_ai)

        if result is None or "error" in result:
            return jsonify({"error": result.get("error", "Impossible d'analyser le fichier.")}), 500

        # Sauvegarder le rapport JSON
        report_name = filename + "_report.json"
        report_path = os.path.join(REPORTS_DIR, report_name)
        report_data = {
            "report_generated": result.get("metadata", {}).get("analysis_timestamp", ""),
            "total_emails_analyzed": 1,
            "analyses": [result],
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        return jsonify(report_data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Erreur d'analyse: {str(e)}"}), 500
    finally:
        # Nettoyer le fichier temporaire
        if "tmp_path" in locals() and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.route("/api/demo", methods=["GET"])
def demo_analysis():
    """Lance l'analyse sur l'email de démonstration."""
    try:
        demo_path = create_demo_email()
        analyzer = PhishingAnalyzer(demo_path)
        result = analyzer.analyze(enable_ai=True)

        if result is None or "error" in result:
            return jsonify({"error": result.get("error", "Erreur lors de l'analyse demo.")}), 500

        report_data = {
            "report_generated": result.get("metadata", {}).get("analysis_timestamp", ""),
            "total_emails_analyzed": 1,
            "analyses": [result],
        }
        return jsonify(report_data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Erreur: {str(e)}"}), 500
    finally:
        if "demo_path" in locals() and os.path.exists(demo_path):
            os.unlink(demo_path)


@app.route("/api/reports", methods=["GET"])
def list_reports():
    """Liste les rapports JSON disponibles."""
    reports = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.endswith(".json"):
            path = os.path.join(REPORTS_DIR, f)
            reports.append({
                "filename": f,
                "size": os.path.getsize(path),
                "modified": os.path.getmtime(path),
            })
    return jsonify(reports)


@app.route("/api/reports/<filename>", methods=["GET"])
def get_report(filename):
    """Récupère un rapport JSON spécifique."""
    if not filename.endswith(".json"):
        return jsonify({"error": "Format invalide"}), 400
    return send_from_directory(REPORTS_DIR, filename)


# ── Rapport d'incident SOC ──

# Stocke la dernière analyse pour la génération de rapports
_last_analysis = {}


@app.route("/api/report/pdf", methods=["POST"])
def generate_pdf():
    """Génère un rapport d'incident SOC en PDF."""
    try:
        from scripts.report_generator import generate_pdf_report
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Données d'analyse manquantes."}), 400
        pdf_bytes = generate_pdf_report(data)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Rapport_Incident_Phishing.pdf"}
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Erreur génération PDF: {str(e)}"}), 500


@app.route("/api/report/docx", methods=["POST"])
def generate_docx():
    """Génère un rapport d'incident SOC en DOCX."""
    try:
        from scripts.report_generator import generate_docx_report
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Données d'analyse manquantes."}), 400
        docx_bytes = generate_docx_report(data)
        return Response(
            docx_bytes,
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename=Rapport_Incident_Phishing.docx"}
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Erreur génération DOCX: {str(e)}"}), 500


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Forensics Web App")
    parser.add_argument("--port", type=int, default=8080, help="Port (défaut: 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Host (défaut: 0.0.0.0)")
    parser.add_argument("--debug", action="store_true", help="Mode debug")
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  Phishing Email Forensics — Web Dashboard")
    print(f"  http://localhost:{args.port}")
    print(f"{'='*50}\n")

    app.run(host=args.host, port=args.port, debug=args.debug)
