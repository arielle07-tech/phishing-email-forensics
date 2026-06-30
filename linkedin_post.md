# Post LinkedIn — Phishing Email Forensics

---

Je viens de terminer un projet perso en cybersécurité : une plateforme d'analyse forensique d'emails de phishing.

L'idée ? Automatiser ce qu'un analyste SOC fait manuellement : vérifier les headers, extraire les IOCs, analyser les pièces jointes, et scorer le niveau de risque.

Ce que j'ai construit :

- Un analyseur Python qui parse les fichiers .eml et détecte les indicateurs de compromission (URLs suspectes, IPs, domaines, extensions dangereuses)
- Une vérification automatique SPF / DKIM / DMARC
- Un scoring de risque multi-facteurs (0-100) avec verdict automatique
- Une analyse IA via Google Gemini pour identifier les tactiques de social engineering (framework CIALDINI + MITRE ATT&CK)
- Un dashboard SOC interactif avec kill chain visuelle, radar chart des tactiques, et timeline d'attaque
- Le tout conteneurisé avec Docker

Stack : Python 3.12 | Flask | Google Gemini API | Docker | MITRE ATT&CK | pytest

Le repo est disponible sur GitHub : https://github.com/arielle07-tech/phishing-email-forensics

Ce projet m'a permis de consolider mes compétences en analyse de menaces, forensique email, et développement d'outils de sécurité. C'est aussi mon premier pas vers l'automatisation SOC — un domaine qui me passionne.

Open to work en cybersécurité ! N'hésitez pas à me contacter ou à jeter un œil au repo.

#Cybersécurité #SOC #PhishingAnalysis #MITREATTACK #Python #Docker #ThreatIntelligence #InfoSec #OpenToWork #PortfolioCyber
