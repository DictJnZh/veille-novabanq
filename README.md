# NovaBanq Cyber Threat Monitoring

Pipeline de veille cybersécurité automatisée pour la surveillance des vulnérabilités critiques affectant l’écosystème bancaire et les infrastructures applicatives.

Le projet collecte des flux RSS spécialisés en cybersécurité, analyse les articles à l’aide de mots-clés pondérés, détecte les vulnérabilités critiques (RCE, Zero-Day, CVE, etc.), envoie des alertes email et affiche les résultats dans un dashboard web interactif.

---

# Fonctionnalités

### Veille cybersécurité automatisée

La pipeline :

- collecte des flux RSS cybersécurité
- analyse les articles
- détecte les vulnérabilités critiques
- calcule un score de menace
- classe les menaces par criticité
- envoie des alertes email
- génère des rapports
- alimente un dashboard web

---

# Surveillance continue

La pipeline fonctionne en **mode surveillance continue**.

Elle analyse les flux RSS toutes les 10 minutes 


afin de détecter rapidement :

- vulnérabilités critiques
- exploits actifs
- zero-day
- attaques supply-chain

---

# Détection de vulnérabilités critiques

Le moteur de détection priorise les vulnérabilités majeures comme :

- Log4Shell
- Spring4Shell
- Remote Code Execution (RCE)
- Zero-Day exploits
- Critical CVE
- Authentication bypass
- Privilege escalation

Les vulnérabilités sont classées selon leur criticité.

| Score | Criticité |
|------|------|
| ≥12 | Critique |
| ≥7 | Élevée |
| ≥4 | Moyenne |
| <4 | Faible |

---

# Alerting

Lorsqu'une menace **Critique ou Élevée** est détectée :

- une **alerte email est envoyée**
- les alertes sont **dédupliquées**
- un article ne génère **qu'une seule alerte**

---

# Dashboard Web

Le dashboard permet de :

- visualiser les menaces détectées
- filtrer les vulnérabilités par criticité
- afficher un graphique des menaces
- consulter les articles sources
- voir les mots-clés détectés

Filtres disponibles :

- Tout
- Vulnérabilité critique
- Criticité élevée
- Criticité moyenne
- Criticité faible

Code couleur :

| Niveau | Couleur |
|------|------|
| Critique | Rouge foncé |
| Élevée | Rouge |
| Moyenne | Orange |
| Faible | Vert |

---

# Architecture

Le projet utilise **Docker Compose** pour orchestrer deux services.

RSS feeds
│
▼
Pipeline Python
│
├── scoring des menaces
├── alerting email
├── génération des rapports
│
▼
reports/report.json
│
▼
Dashboard Web

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
├── logs/
│
├── .env
└── README.md


---

# Installation

Cloner le projet :

```bash
git clone https://github.com/VOTRE_USER/veille-novabanq.git
cd veille-novabanq

Créer un fichier .env :

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password

ALERT_FROM=your_email@gmail.com
ALERT_TO=your_email@gmail.com

Lancer la pipeline : 

Docker compose up -d 

le Dashboard : http://localhost:8080 
