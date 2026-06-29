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


# ── Integrations (RTIR, TheHive, JIRA) ──

# Stocke la config du connecteur actif en mémoire
_integration_config = {}
_active_connector = None


def _auto_connect_integration():
    """Auto-connecte l'intégration configurée dans .env au démarrage."""
    global _active_connector, _integration_config
    connector_name = os.environ.get("TICKET_CONNECTOR", "").strip()
    ticket_url = os.environ.get("TICKET_URL", "").strip()
    if not connector_name or not ticket_url:
        return

    from scripts.integrations import get_connector
    config = {
        "url": ticket_url,
        "user": os.environ.get("TICKET_USER", ""),
        "password": os.environ.get("TICKET_PASSWORD", ""),
        "token": os.environ.get("TICKET_TOKEN", ""),
        "api_key": os.environ.get("TICKET_API_KEY", ""),
        "api_token": os.environ.get("TICKET_API_TOKEN", ""),
        "project_key": os.environ.get("TICKET_PROJECT_KEY", "SEC"),
        "verify_ssl": os.environ.get("TICKET_VERIFY_SSL", "true").lower() in ("true", "1", "yes"),
    }
    try:
        connector = get_connector(connector_name, config)
        result = connector.test_connection()
        if result.get("connected"):
            _active_connector = connector
            _integration_config = {"connector": connector_name, "config": config}
            print(f"  [Integration] Connecte a {connector.display_name} ({ticket_url})")
        else:
            print(f"  [Integration] Echec connexion {connector_name}: {result.get('error', '?')}")
    except Exception as e:
        print(f"  [Integration] Erreur: {e}")


_auto_connect_integration()


@app.route("/api/integrations/connectors", methods=["GET"])
def list_connectors():
    """Liste les connecteurs disponibles."""
    from scripts.integrations import list_available_connectors
    connectors = list_available_connectors()
    # Ajouter le statut de connexion
    for c in connectors:
        c["connected"] = (_active_connector is not None and
                         _active_connector.name == c["name"])
    return jsonify(connectors)


@app.route("/api/integrations/connect", methods=["POST"])
def connect_integration():
    """Connecte un outil de ticketing externe."""
    global _integration_config, _active_connector
    from scripts.integrations import get_connector

    data = request.get_json(silent=True)
    if not data or "connector" not in data:
        return jsonify({"error": "Champ 'connector' requis (rtir, thehive, jira)"}), 400

    try:
        connector = get_connector(data["connector"], data.get("config", {}))
        result = connector.test_connection()
        if not result.get("connected"):
            return jsonify({"error": result.get("error", "Connexion échouée")}), 400

        _active_connector = connector
        _integration_config = data
        return jsonify({"status": "connected", "connector": data["connector"], **result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/integrations/disconnect", methods=["POST"])
def disconnect_integration():
    """Déconnecte l'outil de ticketing."""
    global _active_connector, _integration_config
    _active_connector = None
    _integration_config = {}
    return jsonify({"status": "disconnected"})


@app.route("/api/integrations/status", methods=["GET"])
def integration_status():
    """Statut de la connexion active."""
    if _active_connector:
        result = _active_connector.test_connection()
        return jsonify({
            "connected": result.get("connected", False),
            "connector": _active_connector.name,
            "display_name": _active_connector.display_name,
            **result
        })
    return jsonify({"connected": False})


@app.route("/api/integrations/users", methods=["GET"])
def integration_users():
    """Récupère les utilisateurs depuis l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    users = _active_connector.get_users()
    return jsonify(users)


@app.route("/api/integrations/queues", methods=["GET"])
def integration_queues():
    """Récupère les queues/projets depuis l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    queues = _active_connector.get_queues()
    return jsonify(queues)


@app.route("/api/integrations/tickets", methods=["GET"])
def integration_list_tickets():
    """Liste les tickets depuis l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    filters = {k: v for k, v in request.args.items()}
    tickets_list = _active_connector.list_tickets(filters)
    return jsonify(tickets_list)


@app.route("/api/integrations/tickets", methods=["POST"])
def integration_create_ticket():
    """Crée un ticket dans l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Données du ticket manquantes"}), 400
    result = _active_connector.create_ticket(data)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result), 201


@app.route("/api/integrations/tickets/<ticket_id>", methods=["GET"])
def integration_get_ticket(ticket_id):
    """Récupère un ticket depuis l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    result = _active_connector.get_ticket(ticket_id)
    return jsonify(result)


@app.route("/api/integrations/tickets/<ticket_id>", methods=["PUT"])
def integration_update_ticket(ticket_id):
    """Met à jour un ticket dans l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    data = request.get_json(silent=True)
    result = _active_connector.update_ticket(ticket_id, data)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)


@app.route("/api/integrations/tickets/<ticket_id>/comment", methods=["POST"])
def integration_add_comment(ticket_id):
    """Ajoute un commentaire sur un ticket dans l'outil connecté."""
    if not _active_connector:
        return jsonify({"error": "Aucun outil connecté"}), 400
    data = request.get_json(silent=True)
    result = _active_connector.add_comment(
        ticket_id, data.get("text", ""), data.get("author", ""))
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)


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
