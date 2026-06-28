#!/usr/bin/env python3
"""
Module d'Analyse IA pour Phishing Email Forensics
===================================================
Utilise un LLM (Anthropic Claude, OpenAI, Groq, Gemini, ou Ollama local) pour :
- Analyser le contexte sémantique de l'email
- Détecter les tactiques de social engineering (framework CIALDINI + MITRE)
- Évaluer la sophistication de l'attaque
- Générer un résumé d'investigation automatique
- Produire des recommandations contextuelles

Fournisseurs supportés :
    - anthropic : Claude (défaut, recommandé)
    - openai    : GPT-4 / GPT-4o
    - groq      : Llama3 / Mixtral via Groq (rapide)
    - gemini    : Google Gemini (gemini-2.5-flash, etc.)
    - ollama    : Modèles locaux (llama3, mistral, etc.)

Configuration :
    Variables d'environnement :
        AI_PROVIDER=anthropic|openai|groq|gemini|ollama
        ANTHROPIC_API_KEY=sk-ant-...
        OPENAI_API_KEY=sk-...
        GROQ_API_KEY=gsk_...
        GROQ_MODEL=llama-3.3-70b-versatile (défaut)
        GEMINI_API_KEY=AI...
        GEMINI_MODEL=gemini-2.5-flash (défaut)
        OLLAMA_BASE_URL=http://localhost:11434 (défaut)
        OLLAMA_MODEL=llama3 (défaut)

Usage :
    from ai_analyzer import AIPhishingAnalyzer
    ai = AIPhishingAnalyzer(provider="anthropic")
    result = ai.analyze(email_data, basic_analysis)
"""

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def _load_dotenv():
    """Charge les variables depuis .env (sans dépendance externe)."""
    env_paths = [
        Path(__file__).resolve().parent.parent / ".env",  # project root
        Path.cwd() / ".env",
    ]
    for env_path in env_paths:
        if env_path.is_file():
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip()
                    if value and key not in os.environ:
                        os.environ[key] = value
            return

_load_dotenv()


# ──────────────────────────────────────────────
# Prompts système
# ──────────────────────────────────────────────

SYSTEM_PROMPT = """Tu es un analyste senior en cybersécurité spécialisé dans l'investigation de phishing.
Tu analyses des emails suspects avec une approche forensique rigoureuse.

Ton analyse doit couvrir :
1. CONTEXTE SÉMANTIQUE : Quel est le prétexte utilisé ? Quelle est la narrative ?
2. TACTIQUES DE SOCIAL ENGINEERING : Identifie les leviers psychologiques (urgence, autorité, peur, curiosité, réciprocité, rareté)
3. SOPHISTICATION : Évalue le niveau de l'attaquant (amateur/intermédiaire/avancé/APT)
4. CIBLAGE : Est-ce du phishing de masse ou ciblé ? Pourquoi ?
5. RÉSUMÉ EXÉCUTIF : 3-4 phrases pour un décideur non-technique

Réponds UNIQUEMENT en JSON valide, sans markdown, sans commentaires."""

ANALYSIS_PROMPT_TEMPLATE = """Analyse cet email suspect et fournis ton évaluation forensique.

## EMAIL ANALYSÉ

**De:** {from_addr}
**À:** {to_addr}
**Sujet:** {subject}
**Date:** {date}
**Reply-To:** {reply_to}
**Return-Path:** {return_path}

**Corps du message:**
{body}

## RÉSULTATS DE L'ANALYSE TECHNIQUE PRÉLIMINAIRE

**Authentification:**
- SPF: {spf_status}
- DKIM: {dkim_status}
- DMARC: {dmarc_status}

**IOCs détectés:**
- URLs suspectes: {suspicious_urls}
- Mots-clés phishing: {keywords}
- Pièces jointes: {attachments}

**Anomalies headers:** {anomalies}

**Score technique:** {tech_score}/100

## FORMAT DE RÉPONSE ATTENDU

Réponds en JSON avec cette structure exacte :
{{
    "semantic_analysis": {{
        "pretext": "Description du prétexte utilisé par l'attaquant",
        "narrative": "Résumé de la narrative/histoire racontée",
        "target_emotion": "Émotion principale ciblée (peur, urgence, curiosité, etc.)",
        "credibility_assessment": "Évaluation de la crédibilité du leurre (1-10)",
        "language_quality": "Évaluation de la qualité linguistique (1-10, 10=natif parfait)"
    }},
    "social_engineering_tactics": [
        {{
            "tactic": "Nom de la tactique (Urgence, Autorité, Peur, Rareté, etc.)",
            "description": "Comment elle est employée dans cet email",
            "cialdini_principle": "Principe de Cialdini correspondant",
            "effectiveness": "low|medium|high"
        }}
    ],
    "sophistication": {{
        "level": "amateur|intermediate|advanced|apt",
        "score": 1-10,
        "indicators": ["Liste des indicateurs de sophistication ou de manque de sophistication"],
        "likely_threat_actor_profile": "Profil probable de l'attaquant"
    }},
    "targeting": {{
        "type": "mass|targeted|spear|whaling|bec",
        "confidence": "low|medium|high",
        "reasoning": "Pourquoi cette classification"
    }},
    "impersonation": {{
        "impersonated_entity": "Entité usurpée (banque, service IT, dirigeant, etc.)",
        "impersonation_quality": 1-10,
        "red_flags": ["Éléments qui trahissent l'usurpation"]
    }},
    "executive_summary": "Résumé exécutif en 3-4 phrases pour un décideur non-technique",
    "investigation_notes": "Notes complémentaires pour l'analyste SOC",
    "recommended_actions": [
        "Action 1 spécifique et contextualisée",
        "Action 2",
        "Action 3"
    ],
    "mitre_techniques": [
        {{
            "id": "T1566.001",
            "name": "Nom de la technique",
            "relevance": "Comment cette technique est utilisée ici"
        }}
    ],
    "ai_confidence": 0.0-1.0
}}"""


# ──────────────────────────────────────────────
# Classe principale
# ──────────────────────────────────────────────

class AIPhishingAnalyzer:
    """Analyseur IA pour enrichir l'analyse forensique de phishing."""

    def __init__(self, provider=None, api_key=None, model=None):
        self.provider = provider or os.getenv("AI_PROVIDER", "anthropic")
        self.api_key = api_key
        self.model = model
        self._configure_provider()

    def _configure_provider(self):
        """Configure le fournisseur LLM."""
        if self.provider == "anthropic":
            self.api_key = self.api_key or os.getenv("ANTHROPIC_API_KEY")
            self.model = self.model or "claude-sonnet-4-20250514"
            if not self.api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY requis. "
                    "Définir via: export ANTHROPIC_API_KEY=sk-ant-..."
                )

        elif self.provider == "openai":
            self.api_key = self.api_key or os.getenv("OPENAI_API_KEY")
            self.model = self.model or "gpt-4o"
            if not self.api_key:
                raise ValueError(
                    "OPENAI_API_KEY requis. "
                    "Définir via: export OPENAI_API_KEY=sk-..."
                )

        elif self.provider == "groq":
            self.api_key = self.api_key or os.getenv("GROQ_API_KEY")
            self.model = self.model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
            if not self.api_key:
                raise ValueError(
                    "GROQ_API_KEY requis. "
                    "Définir via: export GROQ_API_KEY=gsk_..."
                )

        elif self.provider == "gemini":
            self.api_key = self.api_key or os.getenv("GEMINI_API_KEY")
            self.model = self.model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
            if not self.api_key:
                raise ValueError(
                    "GEMINI_API_KEY requis. "
                    "Définir via: export GEMINI_API_KEY=AI..."
                )

        elif self.provider == "ollama":
            self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            self.model = self.model or os.getenv("OLLAMA_MODEL", "llama3")

        else:
            raise ValueError(f"Fournisseur inconnu: {self.provider}. Utiliser: anthropic, openai, groq, gemini, ollama")

    def analyze(self, email_data: dict, basic_analysis: dict) -> dict:
        """
        Lance l'analyse IA de l'email.

        Args:
            email_data: Données brutes de l'email (headers, body, etc.)
            basic_analysis: Résultat de PhishingAnalyzer (score technique, IOCs, etc.)

        Returns:
            dict avec l'analyse IA structurée
        """
        prompt = self._build_prompt(email_data, basic_analysis)

        try:
            raw_response = self._call_llm(prompt)
            ai_result = self._parse_response(raw_response)
            ai_result["_meta"] = {
                "provider": self.provider,
                "model": self.model,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            return ai_result

        except Exception as e:
            return {
                "error": str(e),
                "error_type": type(e).__name__,
                "_meta": {
                    "provider": self.provider,
                    "model": self.model,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "status": "failed"
                }
            }

    def _build_prompt(self, email_data: dict, basic_analysis: dict) -> str:
        """Construit le prompt d'analyse."""
        meta = basic_analysis.get("metadata", {})
        auth = basic_analysis.get("authentication", {})
        iocs = basic_analysis.get("iocs", {})
        verdict = basic_analysis.get("verdict", {})

        # Extraire le corps depuis email_data ou basic_analysis
        body = email_data.get("body_text", "")
        if not body:
            body = email_data.get("body_html", "(contenu HTML uniquement)")
        if not body:
            body = "(corps non disponible)"

        # Formater les URLs suspectes
        suspicious_urls = []
        for u in iocs.get("urls", []):
            flags = []
            if u.get("suspicious_tld"): flags.append("TLD suspect")
            if u.get("ip_based"): flags.append("IP directe")
            if u.get("url_shortener"): flags.append("raccourcisseur")
            if u.get("mismatched_display"): flags.append(f"texte trompeur: {u.get('display_text', '?')}")
            entry = u.get("url", "")
            if flags:
                entry += f" [{', '.join(flags)}]"
            suspicious_urls.append(entry)

        # Formater les pièces jointes
        attachments = []
        for a in basic_analysis.get("attachments", []):
            att = f"{a['filename']} ({a['content_type']}, {a.get('size_bytes', 0)} bytes)"
            if a.get("suspicious_extension"):
                att += " [EXTENSION SUSPECTE]"
            attachments.append(att)

        return ANALYSIS_PROMPT_TEMPLATE.format(
            from_addr=meta.get("from", "N/A"),
            to_addr=meta.get("to", "N/A"),
            subject=meta.get("subject", "N/A"),
            date=meta.get("date", "N/A"),
            reply_to=meta.get("reply_to", "N/A"),
            return_path=meta.get("return_path", "N/A"),
            body=body[:3000],  # Limiter la taille
            spf_status=auth.get("spf", {}).get("status", "N/A"),
            dkim_status=auth.get("dkim", {}).get("status", "N/A"),
            dmarc_status=auth.get("dmarc", {}).get("status", "N/A"),
            suspicious_urls="\n".join(suspicious_urls) if suspicious_urls else "Aucune",
            keywords=", ".join(iocs.get("phishing_keywords", [])) or "Aucun",
            attachments="\n".join(attachments) if attachments else "Aucune",
            anomalies="\n".join(basic_analysis.get("headers_analysis", {}).get("anomalies", [])) or "Aucune",
            tech_score=verdict.get("score", "N/A")
        )

    def _call_llm(self, prompt: str) -> str:
        """Appelle le LLM selon le fournisseur configuré."""
        if self.provider == "anthropic":
            return self._call_anthropic(prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt)
        elif self.provider == "groq":
            return self._call_groq(prompt)
        elif self.provider == "gemini":
            return self._call_gemini(prompt)
        elif self.provider == "ollama":
            return self._call_ollama(prompt)

    def _call_anthropic(self, prompt: str) -> str:
        """Appel API Anthropic Claude."""
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "model": self.model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}]
        })

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["content"][0]["text"]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Anthropic API error {e.code}: {body}")

    def _call_openai(self, prompt: str) -> str:
        """Appel API OpenAI."""
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"}
        })

        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {e}")

    def _call_groq(self, prompt: str) -> str:
        """Appel API Groq (compatible OpenAI, ultra-rapide)."""
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"}
        })

        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"Groq API error: {e}")

    def _call_gemini(self, prompt: str) -> str:
        """Appel API Google Gemini."""
        import urllib.request

        payload = json.dumps({
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": SYSTEM_PROMPT + "\n\n" + prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 4096,
                "responseMimeType": "application/json"
            }
        })

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            raise RuntimeError(f"Gemini API error: {e}")

    def _call_ollama(self, prompt: str) -> str:
        """Appel API Ollama (local)."""
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.3}
        })

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["response"]
        except Exception as e:
            raise RuntimeError(f"Ollama error: {e}. Vérifier que Ollama est lancé sur {self.base_url}")

    def _parse_response(self, raw: str) -> dict:
        """Parse la réponse JSON du LLM."""
        # Nettoyer les éventuels blocs markdown
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r'^```(?:json)?\s*', '', cleaned)
            cleaned = re.sub(r'\s*```$', '', cleaned)

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Tenter d'extraire le JSON du texte
            match = re.search(r'\{[\s\S]*\}', cleaned)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            return {
                "error": "Impossible de parser la réponse IA",
                "raw_response": raw[:1000]
            }


# ──────────────────────────────────────────────
# Mode offline (sans API) — Analyse heuristique
# ──────────────────────────────────────────────

class OfflineAIAnalyzer:
    """
    Analyse heuristique avancée sans appel API.
    Utile quand aucune clé API n'est disponible.
    Moins précis qu'un LLM mais fournit quand même
    une analyse de social engineering structurée.
    """

    # Patterns de tactiques de social engineering
    TACTICS_PATTERNS = {
        "Urgence": {
            "patterns": [
                r"urgent", r"imm[ée]diat", r"dans \d+ ?h", r"expire",
                r"act now", r"limited time", r"dernier avis", r"last chance",
                r"24\s*h", r"48\s*h", r"avant qu", r"sous peine"
            ],
            "cialdini": "Rareté (Scarcity)",
            "description_template": "L'email crée un sentiment d'urgence pour pousser à l'action sans réflexion"
        },
        "Autorité": {
            "patterns": [
                r"service s[ée]curit[ée]", r"d[ée]partement", r"administration",
                r"direction", r"support technique", r"service client",
                r"bank", r"banque", r"official", r"officiel",
                r"compliance", r"conformit[ée]", r"IT department"
            ],
            "cialdini": "Autorité (Authority)",
            "description_template": "L'attaquant se fait passer pour une entité d'autorité pour inspirer confiance"
        },
        "Peur": {
            "patterns": [
                r"compromis", r"suspicious", r"unauthorized", r"non autoris",
                r"ferm[ée]", r"bloqu[ée]", r"suspendu", r"d[ée]sactiv",
                r"pirat[ée]", r"hack", r"breach", r"violation",
                r"infraction", r"fraude"
            ],
            "cialdini": "Peur (Fear/Loss Aversion)",
            "description_template": "L'email exploite la peur de perdre l'accès ou d'être victime pour provoquer une réaction émotionnelle"
        },
        "Curiosité": {
            "patterns": [
                r"cliquez ici pour", r"click here", r"découvr",
                r"voir le document", r"consultez", r"v[ée]rifi",
                r"check your", r"view your", r"open the"
            ],
            "cialdini": "Engagement (Commitment)",
            "description_template": "L'email attise la curiosité pour inciter au clic"
        },
        "Récompense": {
            "patterns": [
                r"gagn[ée]", r"r[ée]compense", r"cadeau", r"offre",
                r"gratuit", r"prize", r"winner", r"congratulations",
                r"f[ée]licitations", r"bonus", r"remise"
            ],
            "cialdini": "Réciprocité (Reciprocity)",
            "description_template": "L'email promet une récompense pour motiver l'action"
        },
        "Conformité sociale": {
            "patterns": [
                r"tous les utilisateurs", r"all users", r"colleagues",
                r"coll[èe]gues", r"everyone", r"mandatory",
                r"obligatoire", r"required by", r"exig[ée] par"
            ],
            "cialdini": "Preuve sociale (Social Proof)",
            "description_template": "L'email invoque la norme sociale pour pousser à se conformer"
        }
    }

    # Patterns d'usurpation d'identité
    IMPERSONATION_PATTERNS = {
        "Banque/Finance": [r"banque", r"bank", r"paypal", r"credit", r"visa", r"mastercard", r"compte bancaire"],
        "Service IT": [r"helpdesk", r"IT support", r"microsoft", r"office 365", r"google", r"admin"],
        "E-commerce": [r"amazon", r"ebay", r"commande", r"livraison", r"colis", r"dhl", r"fedex", r"ups"],
        "Gouvernement": [r"impots", r"imp[ôo]t", r"caf", r"ameli", r"gouv", r"s[ée]curit[ée] sociale"],
        "Réseau social": [r"facebook", r"instagram", r"linkedin", r"twitter", r"tiktok"],
        "Messagerie": [r"voicemail", r"fax", r"message vocal", r"missed call"]
    }

    def analyze(self, email_data: dict, basic_analysis: dict) -> dict:
        """Analyse heuristique sans API."""
        meta = basic_analysis.get("metadata", {})
        iocs = basic_analysis.get("iocs", {})
        auth = basic_analysis.get("authentication", {})
        verdict = basic_analysis.get("verdict", {})

        body = email_data.get("body_text", "") + " " + email_data.get("body_html", "")
        subject = meta.get("subject", "")
        from_addr = meta.get("from", "")
        full_text = f"{subject} {body} {from_addr}".lower()

        # Détecter les tactiques
        tactics = self._detect_tactics(full_text)

        # Détecter l'usurpation
        impersonation = self._detect_impersonation(full_text, from_addr)

        # Évaluer la sophistication
        sophistication = self._assess_sophistication(basic_analysis, full_text, tactics)

        # Classifier le ciblage
        targeting = self._classify_targeting(basic_analysis, full_text)

        # Générer le résumé
        executive_summary = self._generate_summary(
            meta, verdict, tactics, impersonation, sophistication
        )

        # Mapper MITRE ATT&CK
        mitre = self._map_mitre(basic_analysis, tactics)

        return {
            "semantic_analysis": {
                "pretext": impersonation.get("pretext", "Non déterminé"),
                "narrative": self._extract_narrative(full_text, impersonation),
                "target_emotion": tactics[0]["tactic"] if tactics else "Non identifiée",
                "credibility_assessment": impersonation.get("impersonation_quality", 3),
                "language_quality": self._assess_language_quality(full_text)
            },
            "social_engineering_tactics": tactics,
            "sophistication": sophistication,
            "targeting": targeting,
            "impersonation": impersonation,
            "executive_summary": executive_summary,
            "investigation_notes": self._generate_investigation_notes(basic_analysis, tactics),
            "recommended_actions": self._generate_recommendations(verdict, impersonation, tactics),
            "mitre_techniques": mitre,
            "ai_confidence": 0.6,  # Heuristique = confiance modérée
            "_meta": {
                "provider": "offline_heuristic",
                "model": "rule-based-v1",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "note": "Analyse heuristique — pour une analyse plus fine, configurer un fournisseur LLM"
            }
        }

    def _detect_tactics(self, text: str) -> list:
        tactics = []
        for name, config in self.TACTICS_PATTERNS.items():
            matches = []
            for pattern in config["patterns"]:
                found = re.findall(pattern, text, re.IGNORECASE)
                matches.extend(found)
            if matches:
                effectiveness = "high" if len(matches) >= 3 else "medium" if len(matches) >= 2 else "low"
                tactics.append({
                    "tactic": name,
                    "description": config["description_template"],
                    "cialdini_principle": config["cialdini"],
                    "effectiveness": effectiveness,
                    "matched_indicators": list(set(matches))[:5]
                })
        # Trier par nombre de matches
        tactics.sort(key=lambda t: len(t.get("matched_indicators", [])), reverse=True)
        return tactics

    def _detect_impersonation(self, text: str, from_addr: str) -> dict:
        detected = None
        max_matches = 0
        for entity, patterns in self.IMPERSONATION_PATTERNS.items():
            matches = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
            if matches > max_matches:
                max_matches = matches
                detected = entity

        quality = min(max_matches * 2, 10) if detected else 1
        red_flags = []

        # Vérifier les red flags d'usurpation
        if re.search(r'\.(tk|ml|ga|cf|gq|xyz|top|buzz)$', from_addr, re.I):
            red_flags.append("Domaine expéditeur avec TLD gratuit/suspect")
        if re.search(r'@(gmail|yahoo|hotmail|outlook)\.(com|fr)', from_addr, re.I):
            red_flags.append("Utilisation d'un fournisseur email gratuit pour usurper une entité officielle")
        if not detected:
            red_flags.append("Entité usurpée non clairement identifiable")

        return {
            "impersonated_entity": detected or "Non déterminé",
            "impersonation_quality": quality,
            "red_flags": red_flags,
            "pretext": f"Usurpation de {detected}" if detected else "Prétexte non identifié"
        }

    def _assess_sophistication(self, analysis: dict, text: str, tactics: list) -> dict:
        score = 0
        indicators = []

        # Nombre de tactiques utilisées
        if len(tactics) >= 3:
            score += 3
            indicators.append(f"{len(tactics)} tactiques de SE combinées")
        elif len(tactics) >= 2:
            score += 2

        # Qualité de l'authentification (les attaquants avancés configurent SPF/DKIM)
        auth = analysis.get("authentication", {})
        if auth.get("spf", {}).get("status") == "pass":
            score += 2
            indicators.append("SPF configuré (effort d'authenticité)")
        if auth.get("dkim", {}).get("status") == "pass":
            score += 2
            indicators.append("DKIM configuré")

        # Pièces jointes sophistiquées
        for att in analysis.get("attachments", []):
            if att.get("content_type") in ("application/pdf", "application/vnd.ms-excel"):
                score += 1
                indicators.append("Pièce jointe de type document (plus crédible que .exe)")
            elif att.get("suspicious_extension"):
                indicators.append("Extension exécutable directe (technique basique)")

        # Liens avec texte trompeur
        mismatched = sum(1 for u in analysis.get("iocs", {}).get("urls", []) if u.get("mismatched_display"))
        if mismatched:
            score += 2
            indicators.append("Liens avec texte d'affichage trompeur")

        # Personnalisation
        if re.search(r"(cher|dear)\s+(mr|mme|monsieur|madame|dr)\b", text, re.I):
            score += 2
            indicators.append("Personnalisation avec civilité")

        score = min(score, 10)

        if score >= 8:
            level = "advanced"
        elif score >= 5:
            level = "intermediate"
        elif score >= 3:
            level = "amateur"
        else:
            level = "amateur"

        profiles = {
            "amateur": "Script kiddie ou opérateur de kit de phishing basique",
            "intermediate": "Acteur avec compétences techniques modérées, possible utilisation de frameworks de phishing",
            "advanced": "Acteur sophistiqué, possiblement affilié à un groupe organisé",
            "apt": "Indicateurs d'un groupe APT ou d'une opération étatique"
        }

        return {
            "level": level,
            "score": score,
            "indicators": indicators,
            "likely_threat_actor_profile": profiles[level]
        }

    def _classify_targeting(self, analysis: dict, text: str) -> dict:
        meta = analysis.get("metadata", {})
        to_addr = meta.get("to", "")

        # Heuristiques de ciblage
        if re.search(r"(ceo|cfo|cto|directeur|président|pdg)", text, re.I):
            return {"type": "whaling", "confidence": "medium",
                    "reasoning": "Références à des postes de direction détectées"}
        if re.search(r"(virement|transfert|wire transfer|payment)", text, re.I):
            return {"type": "bec", "confidence": "medium",
                    "reasoning": "Demande de transfert financier détectée"}
        if re.search(r"(cher\s+(monsieur|madame)|dear\s+(mr|ms|mrs))\s+\w+", text, re.I):
            return {"type": "spear", "confidence": "medium",
                    "reasoning": "Email personnalisé avec nom du destinataire"}

        return {"type": "mass", "confidence": "medium",
                "reasoning": "Aucun indicateur de ciblage spécifique détecté — probable campagne de masse"}

    def _assess_language_quality(self, text: str) -> int:
        issues = 0
        # Vérifications basiques
        if re.search(r'[A-Z]{5,}', text):
            issues += 1  # Trop de majuscules
        if text.count('!') > 3:
            issues += 1  # Trop de points d'exclamation
        if len(text) < 100:
            issues += 1  # Trop court
        return max(1, 8 - issues * 2)

    def _extract_narrative(self, text: str, impersonation: dict) -> str:
        entity = impersonation.get("impersonated_entity", "une entité")
        if re.search(r"(compromis|hack|breach|pirat)", text, re.I):
            return f"L'attaquant prétend que le compte de la victime a été compromis et usurpe {entity} pour obtenir des identifiants"
        if re.search(r"(facture|invoice|payment|paiem)", text, re.I):
            return f"L'attaquant envoie une fausse facture/demande de paiement en se faisant passer pour {entity}"
        if re.search(r"(colis|livraison|delivery|shipping)", text, re.I):
            return f"L'attaquant utilise un prétexte de livraison de colis pour inciter au clic"
        if re.search(r"(mot de passe|password|credential|identifiant)", text, re.I):
            return f"L'attaquant prétend que les identifiants doivent être mis à jour auprès de {entity}"
        return f"L'attaquant utilise un prétexte lié à {entity} pour manipuler la victime"

    def _generate_summary(self, meta, verdict, tactics, impersonation, sophistication) -> str:
        level = verdict.get("risk_level", "UNKNOWN")
        score = verdict.get("score", 0)
        entity = impersonation.get("impersonated_entity", "une entité inconnue")
        soph = sophistication.get("level", "amateur")
        tactic_names = [t["tactic"] for t in tactics[:3]]

        summary = (
            f"Email de phishing de niveau {level} (score {score}/100) "
            f"usurpant l'identité de {entity}. "
        )
        if tactic_names:
            summary += f"Les tactiques de social engineering utilisées incluent : {', '.join(tactic_names)}. "
        summary += f"Niveau de sophistication évalué à '{soph}'. "
        if score >= 70:
            summary += "Une investigation immédiate et des actions de confinement sont recommandées."
        elif score >= 45:
            summary += "Une analyse approfondie est recommandée avant toute action."
        else:
            summary += "Le risque est modéré, une vérification manuelle est conseillée."

        return summary

    def _generate_investigation_notes(self, analysis: dict, tactics: list) -> str:
        notes = []
        auth = analysis.get("authentication", {})
        if auth.get("spf", {}).get("status") == "fail":
            notes.append("Le SPF en échec confirme que l'email ne provient pas du domaine affiché.")
        anomalies = analysis.get("headers_analysis", {}).get("anomalies", [])
        if anomalies:
            notes.append(f"Les anomalies de headers ({len(anomalies)}) renforcent la thèse du phishing.")
        if len(tactics) >= 2:
            notes.append(f"La combinaison de {len(tactics)} tactiques de SE indique une attaque structurée.")
        return " ".join(notes) if notes else "Aucune note complémentaire."

    def _generate_recommendations(self, verdict, impersonation, tactics) -> list:
        recs = []
        score = verdict.get("score", 0)
        entity = impersonation.get("impersonated_entity", "")

        if score >= 70:
            recs.append("Quarantaine immédiate de l'email dans toutes les boîtes de réception")
            recs.append("Bloquer les IOCs identifiés sur le proxy, firewall et passerelle mail")
        if score >= 45:
            recs.append("Rechercher d'autres occurrences de cet email dans les logs de messagerie")
            recs.append("Vérifier les logs proxy pour identifier les utilisateurs ayant cliqué")
        if entity:
            recs.append(f"Alerter {entity} (si légitime) de la campagne d'usurpation en cours")
        recs.append("Mettre à jour les règles de détection avec les nouveaux IOCs")
        if any(t["tactic"] in ("Urgence", "Peur") for t in tactics):
            recs.append("Communiquer aux utilisateurs ciblés : ne pas répondre aux emails créant un sentiment d'urgence artificielle")
        return recs[:6]

    def _map_mitre(self, analysis: dict, tactics: list) -> list:
        mitre = []
        attachments = analysis.get("attachments", [])
        urls = analysis.get("iocs", {}).get("urls", [])

        if attachments:
            mitre.append({
                "id": "T1566.001",
                "name": "Phishing: Spearphishing Attachment",
                "relevance": f"{len(attachments)} pièce(s) jointe(s) détectée(s)"
            })
        if urls:
            mitre.append({
                "id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "relevance": f"{len(urls)} URL(s) détectée(s) dans le corps"
            })
        if any(u.get("url_shortener") for u in urls):
            mitre.append({
                "id": "T1608.005",
                "name": "Stage Capabilities: Link Target",
                "relevance": "Utilisation de raccourcisseurs d'URL pour masquer la destination"
            })
        mitre.append({
            "id": "T1598",
            "name": "Phishing for Information",
            "relevance": "Tentative de collecte d'identifiants via ingénierie sociale"
        })
        return mitre


# ──────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────

def create_analyzer(provider=None, api_key=None, model=None):
    """
    Crée l'analyseur approprié.
    Si aucune clé API n'est configurée, utilise le mode offline.
    """
    provider = provider or os.getenv("AI_PROVIDER", "auto")

    if provider == "auto":
        # Détection automatique
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.getenv("GEMINI_API_KEY"):
            provider = "gemini"
        elif os.getenv("GROQ_API_KEY"):
            provider = "groq"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif _check_ollama():
            provider = "ollama"
        else:
            print("[AI] Aucune clé API détectée — mode heuristique offline activé")
            return OfflineAIAnalyzer()

    if provider == "offline":
        return OfflineAIAnalyzer()

    try:
        return AIPhishingAnalyzer(provider=provider, api_key=api_key, model=model)
    except ValueError as e:
        print(f"[AI] {e} — fallback vers le mode offline")
        return OfflineAIAnalyzer()


def _check_ollama() -> bool:
    """Vérifie si Ollama est disponible."""
    import urllib.request
    try:
        url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        urllib.request.urlopen(f"{url}/api/tags", timeout=2)
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("Module AI Analyzer — utiliser via phishing_analyzer.py --ai")
    print(f"\nFournisseurs disponibles :")
    print(f"  ANTHROPIC_API_KEY: {'✓ configuré' if os.getenv('ANTHROPIC_API_KEY') else '✗ non configuré'}")
    print(f"  OPENAI_API_KEY:    {'✓ configuré' if os.getenv('OPENAI_API_KEY') else '✗ non configuré'}")
    print(f"  Ollama local:      {'✓ disponible' if _check_ollama() else '✗ non disponible'}")
    print(f"\nMode offline heuristique : toujours disponible (fallback automatique)")
