import csv
import feedparser
from datetime import datetime, UTC, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
TOOLS_FILE = BASE_DIR / "tools.csv"
SOURCES_FILE = BASE_DIR / "sources.csv"
FINDINGS_FILE = BASE_DIR / "findings.csv"

REMOTE_TERMS = [
    "rmm",
    "remote monitoring and management",
    "remote monitoring & management",
    "remote management",
    "remote access",
    "remote support",
    "remote administration",
    "remote desktop",
    "rat",
    "remote access trojan",
    "remote administration trojan",
    "remote access tool",
    "remote administration tool",
    "remote access software",
    "remote support software",
    "remote monitoring software",
    "lolrmm",
    "living off the land"
]

THREAT_TERMS = [
    "ransomware",
    "phishing",
    "malware",
    "initial access",
    "threat actor",
    "credential theft",
    "infostealer",
    "backdoor",
    "intrusion",
    "compromise",
    "command and control",
    "c2"
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
def is_recent_article(article, days=90):
    published = article.get("published_parsed") or article.get("updated_parsed")

    if not published:
        return False

    article_date = datetime(*published[:6], tzinfo=UTC)
    cutoff_date = datetime.now(UTC) - timedelta(days=days)

    return article_date >= cutoff_date
def main():
    tools = load_csv(TOOLS_FILE)
    sources = load_csv(SOURCES_FILE)
    existing_urls = load_existing_urls()
    matches_found = 0

    for source in sources:
        print(f"Checking source: {source['source']}")
        feed = feedparser.parse(source["rss_url"])

        for article in feed.entries:
            if not is_recent_article(article, days=90):
                continue

            title = article.get("title", "")
            summary = article.get("summary", "")
            link = article.get("link", "")
            text = f"{title} {summary}".lower()

            #if link in existing_urls:
                #continue

            remote_matches = [term for term in REMOTE_TERMS if term in text]
            threat_matches = [term for term in THREAT_TERMS if term in text]

            if not remote_matches and not threat_matches:
                continue

            for tool in tools:
                tool_name = tool["tool"].lower()

                if tool_name not in text:
                    continue

                tool_matches = [tool_name]

                if not tool_matches:
                    continue

                print(f"Tool matches: {tool_matches}")
                print(f"Matched terms: {remote_matches}")

                append_finding({
                    "date_found": datetime.now(UTC).strftime("%Y-%m-%d"),
                    "source": source["source"],
                    "tool": tool["tool"],
                    "article_title": title,
                    "article_url": link,
                    "matched_terms": "; ".join(tool_matches + remote_matches),
                    "status": "New",
                    "notes": ""
                })

                existing_urls.add(link)
                matches_found += 1
                print("\n----------------------------------")
                print(f"Tool: {tool['tool']}")
                print(f"Article: {title}")
                print(f"Matched Tool Terms: {tool_matches}")
                print(f"Matched Context Terms: {remote_matches}")
                print("----------------------------------")

    print(f"Search complete. Matches found: {matches_found}")
if __name__ == "__main__":
    main()