#!/usr/bin/env python3
"""
URL Sandbox Module — Capture d'ecran automatique des URLs suspectes
===================================================================
Utilise Playwright (navigateur headless Chromium) pour :
- Visiter chaque URL suspecte dans un environnement isole
- Capturer une capture d'ecran de la page
- Extraire le titre, les redirections, et le contenu final
- Detecter les indicateurs de phishing visuels

Les captures sont encodees en Base64 pour inclusion dans le rapport JSON.
Requis: pip install playwright && playwright install chromium
"""

import os
import base64
import logging
import time
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Max URLs to sandbox (rate limit protection)
MAX_URLS_TO_SANDBOX = 5
SCREENSHOT_TIMEOUT = 15000  # 15s per page
VIEWPORT = {"width": 1280, "height": 800}


def _is_playwright_available() -> bool:
    """Verifie si Playwright est installe."""
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False


def sandbox_url(url: str, timeout_ms: int = SCREENSHOT_TIMEOUT) -> dict:
    """
    Visite une URL dans un navigateur headless et capture le resultat.
    Retourne: screenshot (base64), titre, url_finale, redirections, indicateurs.
    """
    result = {
        "original_url": url,
        "final_url": "",
        "title": "",
        "screenshot_b64": "",
        "redirects": [],
        "status_code": 0,
        "page_content_length": 0,
        "phishing_indicators": [],
        "error": None,
        "load_time_ms": 0,
    }

    if not _is_playwright_available():
        result["error"] = "Playwright non installe"
        return result

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                ]
            )
            context = browser.new_context(
                viewport=VIEWPORT,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                ignore_https_errors=True,
            )

            page = context.new_page()

            # Track redirections
            redirects = []
            def on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    redirects.append({
                        "from": response.url,
                        "to": response.headers.get('location', ''),
                        "status": response.status
                    })
            page.on("response", on_response)

            # Navigate
            start = time.time()
            try:
                response = page.goto(url, wait_until='networkidle', timeout=timeout_ms)
                result["status_code"] = response.status if response else 0
            except Exception as e:
                # Page might still have loaded partially
                result["error"] = f"Navigation: {str(e)[:100]}"

            result["load_time_ms"] = int((time.time() - start) * 1000)
            result["final_url"] = page.url
            result["title"] = page.title() or ""
            result["redirects"] = redirects

            # Wait a bit for JS rendering
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass

            # Screenshot
            try:
                screenshot_bytes = page.screenshot(full_page=False, type='png')
                result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode('ascii')
            except Exception as e:
                result["error"] = f"Screenshot: {str(e)[:100]}"

            # Analyze page content for phishing indicators
            try:
                content = page.content()
                result["page_content_length"] = len(content)
                lower_content = content.lower()

                indicators = []

                # Login forms
                if '<input' in lower_content and ('password' in lower_content or 'mot de passe' in lower_content):
                    indicators.append("Formulaire de connexion avec champ mot de passe")

                # Brand impersonation in title/content
                brands = ['microsoft', 'office 365', 'outlook', 'onedrive', 'sharepoint',
                          'google', 'gmail', 'apple', 'icloud', 'amazon', 'paypal',
                          'dhl', 'fedex', 'ups', 'maersk', 'bank', 'netflix',
                          'facebook', 'instagram', 'linkedin', 'whatsapp', 'dropbox']
                title_lower = result["title"].lower()
                found_brands = [b for b in brands if b in title_lower or b in lower_content[:3000]]
                if found_brands:
                    # Check if domain matches brand
                    domain = urlparse(result["final_url"]).netloc.lower()
                    fake_brands = [b for b in found_brands if b not in domain]
                    if fake_brands:
                        indicators.append(f"Imitation de marque: {', '.join(fake_brands[:3])} (domaine: {domain})")

                # Suspicious page characteristics
                if len(content) < 500 and ('<meta' in lower_content and 'refresh' in lower_content):
                    indicators.append("Page quasi-vide avec redirection")
                if result["final_url"] != url:
                    indicators.append(f"Redirection detectee vers: {result['final_url']}")
                if redirects:
                    indicators.append(f"{len(redirects)} redirection(s) HTTP")

                # Certificate/security warnings
                if 'not secure' in lower_content or 'connexion non securisee' in lower_content:
                    indicators.append("Avertissement de securite sur la page")

                result["phishing_indicators"] = indicators

            except Exception as e:
                logger.debug(f"Content analysis error: {e}")

            browser.close()

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def sandbox_urls(urls: list, max_urls: int = MAX_URLS_TO_SANDBOX) -> list:
    """
    Sandbox multiple URLs. Priorite aux URLs suspectes.
    Retourne une liste de resultats de sandbox.
    """
    if not _is_playwright_available():
        logger.info("Playwright non disponible — sandboxing desactive")
        return []

    # Prioritize suspicious URLs
    suspicious = [u for u in urls if u.get("suspicious_tld") or u.get("ip_based") or
                  u.get("url_shortener") or u.get("mismatched_display")]
    normal = [u for u in urls if u not in suspicious]
    ordered = suspicious + normal

    results = []
    for url_entry in ordered[:max_urls]:
        url = url_entry.get("url", "") if isinstance(url_entry, dict) else str(url_entry)
        if not url.startswith(('http://', 'https://')):
            continue
        print(f"[SANDBOX] Capture de {url[:80]}...")
        result = sandbox_url(url)
        results.append(result)

    return results


def is_available() -> bool:
    """Verifie si le module de sandboxing est disponible."""
    return _is_playwright_available()
