#!/usr/bin/env python3
"""
mbox_to_eml.py — Convertisseur .mbox → .eml
=============================================
Extrait les emails individuels d'un fichier .mbox (Google Takeout)
et les sauvegarde en fichiers .eml prêts pour phishing_analyzer.py.

Usage:
    python scripts/mbox_to_eml.py <fichier.mbox> [--output <dossier>] [--limit <N>] [--spam-only]

Exemples:
    python scripts/mbox_to_eml.py Spam.mbox
    python scripts/mbox_to_eml.py Spam.mbox --output ./emails_extraits --limit 50
    python scripts/mbox_to_eml.py "Tous les messages.mbox" --spam-only --limit 100
"""

import os
import re
import sys
import mailbox
import argparse
from email.utils import parsedate_to_datetime
from datetime import datetime


def sanitize_filename(name: str, max_len: int = 80) -> str:
    """Nettoie un nom de fichier en retirant les caractères invalides."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    name = re.sub(r'_+', '_', name).strip('_. ')
    return name[:max_len] if name else "sans_sujet"


def is_spam_or_phishing(msg) -> bool:
    """Détecte si un email est dans le dossier Spam/Junk via les headers Gmail."""
    # Gmail X-Gmail-Labels
    labels = msg.get("X-Gmail-Labels", "").lower()
    if any(kw in labels for kw in ["spam", "junk", "trash", "pourriel"]):
        return True

    # X-Spam headers génériques
    spam_status = msg.get("X-Spam-Status", "").lower()
    if spam_status.startswith("yes"):
        return True

    spam_flag = msg.get("X-Spam-Flag", "").lower()
    if spam_flag == "yes":
        return True

    return False


def extract_preview(msg) -> str:
    """Extrait un aperçu du contenu texte (50 premiers caractères)."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                        return text.strip()[:50].replace('\n', ' ')
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(msg.get_content_charset() or 'utf-8', errors='replace')
                return text.strip()[:50].replace('\n', ' ')
        except Exception:
            pass
    return ""


def convert_mbox_to_eml(mbox_path: str, output_dir: str, limit: int = 0, spam_only: bool = False):
    """
    Convertit un fichier .mbox en fichiers .eml individuels.

    Args:
        mbox_path: Chemin vers le fichier .mbox
        output_dir: Dossier de sortie pour les .eml
        limit: Nombre max d'emails à extraire (0 = tous)
        spam_only: Si True, n'extrait que les emails marqués spam/junk
    """
    if not os.path.isfile(mbox_path):
        print(f"[ERREUR] Fichier introuvable : {mbox_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print(f"[MBOX] Ouverture de {mbox_path}...")
    mbox = mailbox.mbox(mbox_path)

    total = 0
    exported = 0
    skipped_not_spam = 0
    errors = 0

    for i, msg in enumerate(mbox):
        total += 1

        if limit and exported >= limit:
            break

        # Filtre spam si demandé
        if spam_only and not is_spam_or_phishing(msg):
            skipped_not_spam += 1
            continue

        try:
            # Extraire les métadonnées pour le nom de fichier
            subject = msg.get("Subject", "sans_sujet")
            from_addr = msg.get("From", "inconnu")
            date_str = msg.get("Date", "")

            # Construire un nom de fichier lisible
            safe_subject = sanitize_filename(subject, 60)

            # Ajouter un index pour éviter les doublons
            filename = f"{exported+1:04d}_{safe_subject}.eml"
            filepath = os.path.join(output_dir, filename)

            # Écrire le .eml
            with open(filepath, 'wb') as f:
                f.write(msg.as_bytes())

            exported += 1

            # Afficher la progression
            preview = extract_preview(msg)
            date_short = ""
            try:
                dt = parsedate_to_datetime(date_str)
                date_short = dt.strftime("%Y-%m-%d")
            except Exception:
                date_short = "????"

            print(f"  [{exported:4d}] {date_short} | {from_addr[:35]:35s} | {safe_subject[:40]}")

        except Exception as e:
            errors += 1
            print(f"  [ERREUR] Email #{total}: {e}")

    print()
    print("=" * 60)
    print(f"  Total dans le mbox  : {total}")
    if spam_only:
        print(f"  Ignores (non-spam)  : {skipped_not_spam}")
    print(f"  Exportes en .eml    : {exported}")
    if errors:
        print(f"  Erreurs             : {errors}")
    print(f"  Dossier de sortie   : {os.path.abspath(output_dir)}")
    print("=" * 60)

    if exported > 0:
        print()
        print("Pour analyser un email :")
        print(f'  python scripts/phishing_analyzer.py "{output_dir}/{filename}"')


def main():
    parser = argparse.ArgumentParser(
        description="Convertit un fichier .mbox (Google Takeout) en fichiers .eml individuels.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python scripts/mbox_to_eml.py Spam.mbox
  python scripts/mbox_to_eml.py Spam.mbox --output ./phishing_samples --limit 50
  python scripts/mbox_to_eml.py "All mail.mbox" --spam-only --limit 100

Google Takeout:
  1. Va sur https://takeout.google.com
  2. Deselectionne tout, coche uniquement "Courrier"
  3. Clique "Toutes les donnees de courrier sont incluses"
  4. Selectionne uniquement "Spam" (ou "Tous les messages" + --spam-only)
  5. Telecharge et extrais le .mbox
        """)
    parser.add_argument("mbox_file", help="Chemin vers le fichier .mbox")
    parser.add_argument("--output", "-o", default="./extracted_emails",
                        help="Dossier de sortie (default: ./extracted_emails)")
    parser.add_argument("--limit", "-l", type=int, default=0,
                        help="Nombre max d'emails a extraire (0 = tous)")
    parser.add_argument("--spam-only", "-s", action="store_true",
                        help="N'extraire que les emails marques spam/junk")

    args = parser.parse_args()
    convert_mbox_to_eml(args.mbox_file, args.output, args.limit, args.spam_only)


if __name__ == "__main__":
    main()
