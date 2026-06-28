# Phishing Email Forensics

Plateforme d'analyse forensique automatisee d'emails de phishing, avec analyse IA (Google Gemini) et dashboard SOC interactif.

![Dashboard](https://img.shields.io/badge/Dashboard-SOC-00d4ff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![AI](https://img.shields.io/badge/AI-Gemini-8E75B2?style=for-the-badge&logo=google&logoColor=white)

## Fonctionnalites

- **Analyse automatisee** : parsing d'emails `.eml`, extraction de metadonnees, headers, IOCs
- **Verification d'authentification** : SPF, DKIM, DMARC
- **Detection d'IOCs** : URLs suspectes, IPs, domaines, mots-cles phishing
- **Analyse de pieces jointes** : hash MD5/SHA256, detection d'extensions suspectes
- **Scoring de risque** : algorithme multi-facteurs (0-100) avec verdict automatique
- **Analyse IA** : detection de tactiques de social engineering (framework CIALDINI + MITRE ATT&CK)
- **Dashboard SOC** : interface web avec upload `.eml`, kill chain visuelle, radar chart, timeline d'attaque
- **Multi-provider IA** : Gemini, Groq, OpenAI, Anthropic, Ollama

## Architecture

```
phishing-email-forensics/
├── scripts/
│   ├── phishing_analyzer.py   # Analyseur principal
│   └── ai_analyzer.py         # Module d'analyse IA/LLM
├── webapp.py                  # Serveur Flask (dashboard + API)
├── dashboard.html             # Dashboard SOC interactif
├── samples/                   # Fichiers .eml a analyser
├── reports/                   # Rapports JSON generes
├── Dockerfile                 # Image Docker
├── docker-compose.yml         # Orchestration des services
├── .devcontainer/             # Dev Container VS Code
└── .env.example               # Template de configuration
```

## Demarrage rapide

### Avec Docker (recommande)

```bash
# Cloner le repo
git clone https://github.com/arielle07-tech/phishing-email-forensics.git
cd phishing-email-forensics

# Configurer l'API Gemini
cp .env.example .env
# Editer .env avec votre cle GEMINI_API_KEY

# Lancer le dashboard
docker compose up dashboard --build -d

# Ouvrir http://localhost:8080
```

### En ligne de commande

```bash
# Analyser un email
docker compose run analyzer samples/demo_phishing.eml --ai

# Demo integree
docker compose run analyzer --demo --ai
```

### Dev Container (VS Code)

1. Ouvrir le projet dans VS Code
2. `F1` > "Dev Containers: Reopen in Container"
3. Terminal : `python scripts/phishing_analyzer.py --demo --ai`

## Configuration

Copier `.env.example` vers `.env` et configurer le provider IA :

```bash
# Provider IA (auto = detection automatique)
AI_PROVIDER=gemini

# Google Gemini (recommande, gratuit)
GEMINI_API_KEY=votre_cle_ici
GEMINI_MODEL=gemini-2.5-flash
```

Providers supportes : `gemini`, `groq`, `openai`, `anthropic`, `ollama`

## API

Le serveur Flask expose les endpoints suivants :

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/` | GET | Dashboard SOC |
| `/api/analyze` | POST | Upload et analyse d'un `.eml` |
| `/api/demo` | GET | Analyse de l'email demo |
| `/api/reports` | GET | Liste des rapports |
| `/api/reports/<file>` | GET | Telecharger un rapport |
| `/api/report/pdf` | POST | Generer rapport d'incident PDF |
| `/api/report/docx` | POST | Generer rapport d'incident DOCX |

## Stack technique

- **Python 3.12** — analyse forensique (stdlib uniquement pour le core)
- **Flask** — serveur web et API REST
- **Google Gemini API** — analyse IA de social engineering
- **Docker** — containerisation et deploiement
- **MITRE ATT&CK** — framework de classification des techniques d'attaque
- **CIALDINI** — framework d'analyse des tactiques de manipulation

## Exemple de resultat

L'analyse d'un email de phishing produit :

- **Score de risque** : 100/100 (CRITICAL)
- **Authentification** : SPF fail, DKIM fail, DMARC fail
- **IOCs** : URLs suspectes, IPs, raccourcisseurs
- **Tactiques SE** : Urgence, Autorite, Peur (effectiveness: HIGH)
- **MITRE ATT&CK** : T1566.001, T1566.002, T1598
- **Verdict** : Phishing confirme — investigation immediate recommandee

## Auteur

**Arielle Yao** — Cybersecurity Analyst

## Licence

MIT License
