import csv
import feedparser
from datetime import datetime, UTC
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
TOOLS_FILE = BASE_DIR / "tools.csv"
SOURCES_FILE = BASE_DIR / "sources.csv"
FINDINGS_FILE = BASE_DIR / "findings.csv"

MALICIOUS_TERMS = [
    "ransomware", "phishing", "malware", "abuse", "threat actor",
    "intrusion", "initial access", "backdoor", "credential theft",
    "campaign", "compromise", "remote access"
]

def load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def load_existing_urls():
    if not FINDINGS_FILE.exists():
        return set()
    with open(FINDINGS_FILE, newline="", encoding="utf-8") as f:
        return {row.get("article_url", "") for row in csv.DictReader(f)}

def append_finding(row):
    fieldnames = [
        "date_found", "source", "tool", "article_title",
        "article_url", "matched_terms", "status", "notes"
    ]

    file_exists = FINDINGS_FILE.exists()

    with open(FINDINGS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        if not file_exists or FINDINGS_FILE.stat().st_size == 0:
            writer.writeheader()

        writer.writerow(row)

def main():
    tools = load_csv(TOOLS_FILE)
    sources = load_csv(SOURCES_FILE)
    existing_urls = load_existing_urls()

    for source in sources:
        feed = feedparser.parse(source["rss_url"])

        for article in feed.entries:
            title = article.get("title", "")
            summary = article.get("summary", "")
            link = article.get("link", "")
            text = f"{title} {summary}".lower()

            if link in existing_urls:
                continue

            malicious_matches = [term for term in MALICIOUS_TERMS if term in text]

            for tool in tools:
                keywords = [k.strip().lower() for k in tool["keywords"].split(",")]
                tool_matches = [k for k in keywords if k in text]

                if tool_matches and malicious_matches:
                    append_finding({
                        "date_found": datetime.now(UTC).strftime("%Y-%m-%d"),
                        "source": source["source"],
                        "tool": tool["tool"],
                        "article_title": title,
                        "article_url": link,
                        "matched_terms": "; ".join(tool_matches + malicious_matches),
                        "status": "New",
                        "notes": ""
                    })
                    existing_urls.add(link)
                    print(f"Match found: {tool['tool']} - {title}")

if __name__ == "__main__":
    main()