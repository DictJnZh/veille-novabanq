import os
import json
import feedparser
from datetime import datetime

SOURCES_FILE = "/app/config/sources.txt"
KEYWORDS_FILE = "/app/config/keywords.txt"
REPORT_MD = "/app/reports/report.md"
REPORT_JSON = "/app/reports/report.json"
LOG_FILE = "/app/logs/pipeline.log"


def load_sources():
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def load_keywords():
    keywords = {}
    with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            keywords[key.lower()] = int(value)
    return keywords


def score_article(text, keywords):
    text = text.lower()
    score = 0
    found = []

    for keyword, weight in keywords.items():
        if keyword in text:
            score += weight
            found.append(keyword)

    return score, found


def get_criticality(score):
    if score >= 7:
        return "Élevée"
    elif score >= 4:
        return "Moyenne"
    else:
        return "Faible"


def main():
    os.makedirs("/app/reports", exist_ok=True)
    os.makedirs("/app/logs", exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sources = load_sources()
    keywords = load_keywords()

    results = []
    seen_links = set()

    for source in sources:
        feed = feedparser.parse(source)

        for entry in feed.entries[:10]:
            title = getattr(entry, "title", "")
            link = getattr(entry, "link", "")
            summary = getattr(entry, "summary", "")

            if not link or link in seen_links:
                continue

            seen_links.add(link)

            text = f"{title} {summary}"
            score, found_keywords = score_article(text, keywords)

            if score > 0:
                results.append({
                    "title": title,
                    "link": link,
                    "score": score,
                    "criticality": get_criticality(score),
                    "keywords": found_keywords
                })

    results.sort(key=lambda x: x["score"], reverse=True)

    # JSON report
    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Markdown report
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("# Rapport de veille cyber - NovaBanq\n\n")
        f.write(f"Généré le : {now}\n\n")

        if not results:
            f.write("Aucune menace détectée.\n")
        else:
            for i, article in enumerate(results[:10], start=1):
                f.write(f"## {i}. {article['title']}\n")
                f.write(f"- Criticité : {article['criticality']}\n")
                f.write(f"- Score : {article['score']}\n")
                f.write(f"- Mots-clés détectés : {', '.join(article['keywords'])}\n")
                f.write(f"- Lien : {article['link']}\n\n")

    # Log
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("Pipeline exécutée avec succès\n")
        f.write(f"Date : {now}\n")
        f.write(f"Articles détectés : {len(results)}\n")

    print("Rapport de veille généré avec succès")


if __name__ == "__main__":
    main()
