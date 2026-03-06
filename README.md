# NovaBanq Cyber Threat Monitoring

Pipeline de veille cybersécurité automatisée pour le projet NovaBanq.

Cette application collecte des flux RSS de cybersécurité, analyse les articles selon des mots-clés critiques, calcule un score de menace et affiche les résultats dans un dashboard web interactif.

---

# Architecture

Le projet est composé de deux services Docker :

1. **Pipeline de veille**
   - collecte les flux RSS
   - analyse les articles
   - calcule un score de criticité
   - génère un rapport JSON et Markdown

2. **Dashboard Web**
   - lit le rapport JSON
   - affiche les menaces
   - graphique de criticité
   - code couleur selon le niveau de risque

---

# Structure du projet

veille-novabanq/
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
│
├── config/
│ ├── sources.txt
│ └── keywords.txt
│
├── scripts/
│ └── pipeline.py
│
├── web/
│ └── index.html
│
├── reports/
│
└── logs/


---

# Fonctionnement de la pipeline

1. Lecture des sources RSS
2. Analyse des articles
3. Détection de mots-clés
4. Calcul d'un score de menace
5. Classification par criticité

| Score | Criticité |
|------|------|
| 7+ | Élevée |
| 4-6 | Moyenne |
| 1-3 | Faible |

---

# Dashboard

Le dashboard web affiche :

http://localhost:8080

- graphique des menaces
- liste des articles détectés
- score de criticité
- mots-clés détectés

Code couleur :

🔴 Élevée (rouge)
🟠 Moyenne (orange)
🟢 Faible (vert) 

---

# Installation

Cloner le projet :

```bash
git clone https://github.com/VOTRE_USER/veille-novabanq.git
cd veille-novabanq
docker compose up -d



