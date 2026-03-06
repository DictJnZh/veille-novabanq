import os
import json
import time
import feedparser
import smtplib
from email.message import EmailMessage
from datetime import datetime

SOURCES_FILE = "/app/config/sources.txt"
KEYWORDS_FILE = "/app/config/keywords.txt"
REPORT_MD = "/app/reports/report.md"
REPORT_JSON = "/app/reports/report.json"
LOG_FILE = "/app/logs/pipeline.log"
STATE_FILE = "/app/logs/alerted_articles.json"

POLL_INTERVAL_SECONDS = 600  # 10 minutes


def ensure_dirs():
    os.makedirs("/app/reports", exist_ok=True)
    os.makedirs("/app/logs", exist_ok=True)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_sources():
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def load_keywords():
    keywords = {}
    with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            keywords[key.strip().lower()] = int(value.strip())
    return keywords


def load_alerted_state():
    if not os.path.exists(STATE_FILE):
        return []
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


def save_alerted_state(alerted_links):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(list(set(alerted_links))), f, indent=2, ensure_ascii=False)


def score_article(text, keywords):
    text_lower = text.lower()
    score = 0
    found = []

    for keyword, weight in keywords.items():
        if keyword in text_lower:
            score += weight
            found.append(keyword)

    return score, found


def classify_article(text, base_score, found_keywords):
    """
    Renforce la criticité pour les vulnérabilités critiques / RCE / zero-day.
    """
    text_lower = text.lower()
    score = base_score
    tags = list(found_keywords)

    critical_markers = {
        "log4shell": 8,
        "spring4shell": 8,
        "reactos": 0,  # évite faux positif éventuel si "react" est trop large dans keywords
        "zero-day": 6,
        "0-day": 6,
        "rce": 6,
        "remote code execution": 7,
        "critical vulnerability": 7,
        "critical cve": 7,
        "actively exploited": 8,
        "unauthenticated": 4,
        "deserialization": 4,
        "command injection": 6,
        "code injection": 6,
        "authentication bypass": 6,
        "privilege escalation": 5,
        "cve-": 2,
        "apache": 1,
        "vmware": 2,
        "fortinet": 2,
        "citrix": 2,
        "ivanti": 2,
        "confluence": 2,
        "exchange": 2,
        "moveit": 4,
    }

    matched_markers = []
    for marker, bonus in critical_markers.items():
        if marker in text_lower:
            score += bonus
            matched_markers.append(marker)

    tags.extend([m for m in matched_markers if m not in tags])

    category = "Cybermenace générale"
    if any(x in text_lower for x in ["vulnerability", "zero-day", "cve-", "rce", "remote code execution"]):
        category = "Vulnérabilité critique"
    elif any(x in text_lower for x in ["fraud", "payment", "banking trojan", "phishing"]):
        category = "Fraude / Menace financière"
    elif any(x in text_lower for x in ["oauth", "authentication", "token", "session", "identity"]):
        category = "Authentification / Accès"
    elif any(x in text_lower for x in ["supply chain", "dependency", "library", "sdk"]):
        category = "Supply chain"

    if score >= 12:
        criticality = "Critique"
    elif score >= 7:
        criticality = "Élevée"
    elif score >= 4:
        criticality = "Moyenne"
    else:
        criticality = "Faible"

    return score, criticality, category, sorted(list(set(tags)))


def send_email_alert(article):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    alert_from = os.getenv("ALERT_FROM")
    alert_to = os.getenv("ALERT_TO")

    if not all([smtp_host, smtp_user, smtp_password, alert_from, alert_to]):
        return False, "Configuration SMTP incomplète"

    msg = EmailMessage()
    msg["Subject"] = f"[ALERTE CYBER] {article['criticality']} - {article['title'][:120]}"
    msg["From"] = alert_from
    msg["To"] = alert_to

    msg.set_content(
        f"""Une menace importante a été détectée par la veille NovaBanq.

Titre : {article['title']}
Catégorie : {article['category']}
Criticité : {article['criticality']}
Score : {article['score']}
Mots-clés / indicateurs : {', '.join(article['keywords'])}
Lien : {article['link']}

Date : {now_str()}
"""
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True, "Alerte email envoyée"
    except Exception as e:
        return False, f"Erreur SMTP : {e}"


def write_reports(results):
    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    critique_count = sum(1 for r in results if r["criticality"] == "Critique")
    high_count = sum(1 for r in results if r["criticality"] == "Élevée")
    medium_count = sum(1 for r in results if r["criticality"] == "Moyenne")
    low_count = sum(1 for r in results if r["criticality"] == "Faible")

    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("# Rapport de veille cyber - NovaBanq\n\n")
        f.write(f"Généré le : {now_str()}\n\n")
        f.write("## Résumé\n\n")
        f.write(f"- Total d'articles pertinents : {len(results)}\n")
        f.write(f"- Critique : {critique_count}\n")
        f.write(f"- Élevée : {high_count}\n")
        f.write(f"- Moyenne : {medium_count}\n")
        f.write(f"- Faible : {low_count}\n\n")

        if not results:
            f.write("Aucune menace détectée.\n")
            return

        f.write("## Top menaces\n\n")
        for i, article in enumerate(results[:15], start=1):
            f.write(f"### {i}. {article['title']}\n")
            f.write(f"- Catégorie : {article['category']}\n")
            f.write(f"- Criticité : {article['criticality']}\n")
            f.write(f"- Score : {article['score']}\n")
            f.write(f"- Mots-clés détectés : {', '.join(article['keywords'])}\n")
            f.write(f"- Lien : {article['link']}\n\n")


def append_log(lines):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_once():
    ensure_dirs()

    log_lines = [f"[{now_str()}] Début d'exécution"]
    sources = load_sources()
    keywords = load_keywords()
    alerted_links = load_alerted_state()

    results = []
    seen_links = set()

    log_lines.append(f"Sources chargées : {len(sources)}")
    log_lines.append(f"Mots-clés chargés : {len(keywords)}")
    log_lines.append(f"Alertes déjà envoyées : {len(alerted_links)}")

    for source in sources:
        log_lines.append(f"Lecture source : {source}")
        try:
            feed = feedparser.parse(source)
        except Exception as e:
            log_lines.append(f"Erreur lecture source {source} : {e}")
            continue

        for entry in feed.entries[:20]:
            title = getattr(entry, "title", "").strip()
            link = getattr(entry, "link", "").strip()
            summary = getattr(entry, "summary", "").strip()

            if not title or not link or link in seen_links:
                continue

            seen_links.add(link)

            full_text = f"{title} {summary}"
            base_score, found_keywords = score_article(full_text, keywords)

            if base_score <= 0:
                continue

            final_score, criticality, category, final_keywords = classify_article(
                full_text,
                base_score,
                found_keywords
            )

            article = {
                "title": title,
                "link": link,
                "score": final_score,
                "criticality": criticality,
                "category": category,
                "keywords": final_keywords,
            }
            results.append(article)

            # Alerte sur Critique et Élevée
            if criticality in ["Critique", "Élevée"] and link not in alerted_links:
                ok, message = send_email_alert(article)
                log_lines.append(f"Alerte '{criticality}' pour '{title}' : {message}")
                if ok:
                    alerted_links.append(link)

    # Tri par criticité puis score
    severity_order = {"Critique": 4, "Élevée": 3, "Moyenne": 2, "Faible": 1}
    results.sort(key=lambda x: (severity_order.get(x["criticality"], 0), x["score"]), reverse=True)

    write_reports(results)
    save_alerted_state(alerted_links)

    critique_count = sum(1 for r in results if r["criticality"] == "Critique")
    high_count = sum(1 for r in results if r["criticality"] == "Élevée")
    log_lines.append(f"Articles pertinents : {len(results)}")
    log_lines.append(f"Critiques : {critique_count}")
    log_lines.append(f"Élevées : {high_count}")
    log_lines.append(f"[{now_str()}] Fin d'exécution")

    append_log(log_lines)
    print(f"[{now_str()}] Rapport généré - {len(results)} article(s)", flush=True)


def main():
    ensure_dirs()
    append_log([f"[{now_str()}] Surveillance continue démarrée (intervalle {POLL_INTERVAL_SECONDS}s)"])

    while True:
        try:
            run_once()
        except Exception as e:
            append_log([f"[{now_str()}] Erreur critique pipeline : {e}"])
            print(f"Erreur pipeline : {e}", flush=True)

        print(f"Prochaine exécution dans {POLL_INTERVAL_SECONDS // 60} minute(s)", flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
