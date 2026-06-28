# Phishing Email Forensics — Roadmap

## Vision

Transformer un outil d'analyse basique en plateforme forensique intelligente qui se distingue des solutions existantes (PhishTool, PhishER, Sublime Security) par quatre axes d'innovation.

---

## Architecture actuelle (v1.0) ✅

| Composant | Fichier | Statut |
|-----------|---------|--------|
| Analyseur core | `scripts/phishing_analyzer.py` | Livré |
| Module IA | `scripts/ai_analyzer.py` | Livré (heuristique + LLM) |
| Playbook investigation | `Playbook_Investigation_Phishing.docx` | Livré |
| Dashboard interactif | `dashboard.html` | Livré (avec panneaux IA) |
| Email de démo | `samples/demo_phishing.eml` | Livré |

---

## Axe 1 — Analyse IA / LLM (Priorité 1)

**Objectif :** Passer du pattern matching statique à la compréhension contextuelle.

**Statut actuel :** v1 livrée (mode offline heuristique + support Claude/OpenAI/Ollama).

### Évolutions prévues

**v1.1 — Analyse conversationnelle**
- Analyser les chaînes de réponse (thread) pour détecter le BEC multi-étapes
- Détecter les changements de ton/style entre emails d'un même thread
- Comparer le style d'écriture avec les communications habituelles de l'expéditeur

**v1.2 — Analyse visuelle**
- OCR + analyse des logos contrefaits dans les emails HTML
- Comparaison de similarité visuelle avec les templates légitimes connus
- Détection des pixels de tracking invisibles

**v1.3 — Threat Intel augmentée**
- Enrichissement automatique des IOCs via VirusTotal / AbuseIPDB / URLhaus APIs
- Corrélation avec les campagnes connues (PhishTank, OpenPhish)
- Attribution probabiliste du threat actor

**Stack technique :** Python, API Anthropic/OpenAI, Pillow/OpenCV pour analyse visuelle, APIs Threat Intel.

---

## Axe 2 — Timeline forensique interactive (Priorité 2)

**Objectif :** Reconstituer visuellement la chaîne d'attaque complète.

### Fonctionnalités

**v2.0 — Timeline email**
- Visualisation chronologique : envoi → routage (hops) → réception → ouverture → clic
- Parsing des headers Received pour extraire les timestamps de chaque hop
- Géolocalisation des IPs de la chaîne de routage (MaxMind GeoIP)

**v2.1 — Corrélation SIEM**
- Import de logs (Splunk/Elastic JSON, CSV) pour corréler les événements post-clic
- Timeline unifiée : email + proxy + endpoint + authentification
- Détection automatique des pivots (clic → téléchargement → exécution → mouvement latéral)

**v2.2 — Visualisation réseau**
- Graphe d'infrastructure de l'attaquant (domaines → IPs → ASN)
- Vue de propagation au sein de l'organisation (qui a reçu, qui a cliqué, qui a transmis)

**Stack technique :** D3.js pour les visualisations, Leaflet.js pour la cartographie, MaxMind GeoLite2.

---

## Axe 3 — Simulation offensive (Priorité 3)

**Objectif :** Transformer chaque attaque détectée en exercice de sensibilisation.

### Fonctionnalités

**v3.0 — Générateur de campagnes**
- À partir d'un phishing réel analysé, générer une variante inoffensive pour tester les utilisateurs
- Personnalisation : remplacer les IOCs par des domaines de test contrôlés
- Templates paramétrables par secteur (banque, IT, RH, logistique)

**v3.1 — Scoring utilisateur**
- Tracker quels utilisateurs cliquent sur les simulations
- Score de vigilance par utilisateur/département
- Recommandations de formation ciblées

**v3.2 — Reporting campagne**
- Dashboard dédié aux campagnes de simulation
- Métriques : taux de clic, temps avant signalement, récidive
- Évolution dans le temps (la sensibilisation fonctionne-t-elle ?)

**Stack technique :** Python (génération), GoPhish API (envoi), Dashboard React/HTML.

**Considérations éthiques :**
- Toujours obtenir l'autorisation de la direction et du service juridique
- Ne jamais collecter de vrais identifiants, même en simulation
- Approche pédagogique, jamais punitive

---

## Axe 4 — Scoring adaptatif (Priorité 4)

**Objectif :** Un scoring qui apprend le "normal" de l'organisation.

### Fonctionnalités

**v4.0 — Profil de communication**
- Construire un profil baseline par expéditeur fréquent (horaires, style, domaines)
- Détecter les anomalies : "le CFO n'envoie jamais d'emails le dimanche à 3h"
- Score de déviation par rapport au profil établi

**v4.1 — Machine learning**
- Modèle de classification entraîné sur les emails analysés (phishing vs légitime)
- Features : headers, authentification, contenu, métadonnées temporelles
- Feedback loop : les analystes confirment/infirment les verdicts → le modèle s'améliore

**v4.2 — Scoring organisationnel**
- Pondération du score selon le contexte : rôle du destinataire, période (fin de mois = plus de phishing financier), campagnes en cours
- Intégration avec l'annuaire (AD/LDAP) pour enrichir le contexte

**Stack technique :** scikit-learn / XGBoost pour le ML, SQLite pour le stockage des profils.

---

## Planning indicatif

| Phase | Axe | Estimation | Prérequis |
|-------|-----|------------|-----------|
| v1.1 | IA — Analyse conversationnelle | 2-3 semaines | v1.0 ✅ |
| v1.2 | IA — Analyse visuelle | 2 semaines | Pillow/OpenCV |
| v1.3 | IA — Threat Intel augmentée | 1-2 semaines | Clés API TI |
| v2.0 | Timeline email | 2 semaines | v1.0 ✅ |
| v2.1 | Timeline SIEM | 3 semaines | Accès logs SIEM |
| v3.0 | Simulation — Générateur | 3 semaines | v1.0 ✅ |
| v3.1 | Simulation — Scoring | 2 semaines | v3.0 |
| v4.0 | Scoring adaptatif — Baseline | 3-4 semaines | Dataset emails |
| v4.1 | Scoring adaptatif — ML | 4 semaines | v4.0 + dataset labellisé |

---

## Ce qui nous démarque

| Critère | PhishTool | PhishER | **Ce projet** |
|---------|-----------|---------|---------------|
| Analyse IA sémantique | Non | Non | **Oui (LLM + heuristique)** |
| Détection social engineering | Basique | Non | **Avancée (Cialdini + MITRE)** |
| Timeline forensique | Non | Non | **Prévu (v2)** |
| Simulation offensive intégrée | Non | Non | **Prévu (v3)** |
| Scoring adaptatif | Non | Non | **Prévu (v4)** |
| Support français natif | Non | Non | **Oui** |
| Open source / self-hosted | Non | Non | **Oui** |
| Multi-provider IA | N/A | N/A | **Claude + OpenAI + Ollama** |
