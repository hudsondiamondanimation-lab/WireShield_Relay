#!/usr/bin/env python3
"""Update WireShield public threat relay.

This script is intentionally dependency-free so it can run inside GitHub Actions.
It reads trusted public feeds, optional feed secrets, and GitHub issues labeled
`approved-threat`, then writes threat-relay/wireshield-threat-feed.json.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RELAY = ROOT / "threat-relay" / "wireshield-threat-feed.json"
INTEL = ROOT / "threat-relay" / "wireshield-intel-feed.json"
MAX_ENTRIES = 50000
USER_AGENT = "WireShield-Relay-Updater/1.0 (+https://github.com/hudsondiamondanimation-lab/WireShield_Relay)"
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
SAFE_TESTS = [
    {
        "domain": "testsafebrowsing.appspot.com",
        "url": "https://testsafebrowsing.appspot.com/s/phishing.html",
        "type": "phishing test",
        "reports": 10000,
        "confidence": 99,
        "source": "Google Safe Browsing public test host",
        "note": "Safe browser-warning test entry. Use this to confirm WireShield shows its block page.",
    },
    {
        "domain": "testsafebrowsing.appspot.com",
        "url": "https://testsafebrowsing.appspot.com/s/malware.html",
        "type": "malware test",
        "reports": 10000,
        "confidence": 99,
        "source": "Google Safe Browsing public test host",
        "note": "Safe malware-warning test entry. Domain is blocked by WireShield when loaded.",
    },
]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def fetch_text(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def norm_host(value: str) -> str:
    value = (value or "").strip().strip("[]")
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    try:
        parsed = urllib.parse.urlparse(value)
        return (parsed.hostname or "").lower().strip(".")
    except Exception:
        return ""


def norm_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    try:
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        clean = parsed._replace(fragment="")
        return urllib.parse.urlunparse(clean)
    except Exception:
        return ""


def key_for(entry: dict[str, Any]) -> str:
    return norm_host(entry.get("url") or entry.get("domain") or "")


def upsert(entries: dict[str, dict[str, Any]], entry: dict[str, Any]) -> None:
    host = key_for(entry)
    if not host:
        return
    current = entries.get(host, {})
    report_count = max(int(current.get("reports") or 0), int(entry.get("reports") or 1))
    confidence = max(int(current.get("confidence") or 0), int(entry.get("confidence") or 70))
    entries[host] = {
        "domain": host,
        "url": norm_url(entry.get("url") or current.get("url") or host),
        "type": str(entry.get("type") or current.get("type") or "scam")[:80],
        "reports": report_count,
        "confidence": confidence,
        "source": str(entry.get("source") or current.get("source") or "trusted feed")[:220],
        "firstSeen": str(entry.get("firstSeen") or current.get("firstSeen") or today())[:40],
        "lastSeen": str(entry.get("lastSeen") or today())[:40],
        "note": str(entry.get("note") or current.get("note") or "")[:500],
    }


def load_existing() -> dict[str, dict[str, Any]]:
    if not RELAY.exists():
        return {}
    try:
        data = json.loads(RELAY.read_text(encoding="utf-8-sig"))
        raw_entries = data if isinstance(data, list) else data.get("entries", [])
        out: dict[str, dict[str, Any]] = {}
        for item in raw_entries:
            if isinstance(item, dict):
                upsert(out, item)
        return out
    except Exception as exc:
        print(f"warning: could not read existing relay: {exc}", file=sys.stderr)
        return {}


def import_openphish(entries: dict[str, dict[str, Any]]) -> None:
    try:
        text = fetch_text(OPENPHISH_URL)
    except Exception as exc:
        print(f"OpenPhish skipped: {exc}")
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        upsert(entries, {
            "url": line,
            "type": "phishing",
            "reports": 1,
            "confidence": 78,
            "source": "OpenPhish community feed",
            "note": "Imported automatically from OpenPhish community feed.",
        })


def import_phishtank(entries: dict[str, dict[str, Any]]) -> None:
    key = os.environ.get("PHISHTANK_APP_KEY", "").strip()
    candidates = []
    if key:
        candidates.append((f"https://data.phishtank.com/data/{urllib.parse.quote(key)}/online-valid.json", "json", "PhishTank verified keyed feed"))
    # Public/no-key feeds may be rate-limited or unavailable; try them and skip cleanly on 404.
    candidates.extend([
        ("https://data.phishtank.com/data/online-valid.json", "json", "PhishTank public verified feed"),
        ("https://data.phishtank.com/data/online-valid.csv", "csv", "PhishTank public verified feed"),
    ])
    loaded = False
    for url, fmt, source in candidates:
        try:
            text = fetch_text(url)
        except urllib.error.HTTPError as exc:
            print(f"PhishTank {source} skipped: HTTP {exc.code}")
            continue
        except Exception as exc:
            print(f"PhishTank {source} skipped: {exc}")
            continue
        if fmt == "json":
            try:
                data = json.loads(text)
            except Exception as exc:
                print(f"PhishTank {source} skipped: invalid JSON: {exc}")
                continue
            if not isinstance(data, list):
                continue
            for item in data:
                if not isinstance(item, dict) or not item.get("url"):
                    continue
                upsert(entries, {
                    "url": item.get("url"),
                    "type": "phishing",
                    "reports": 1,
                    "confidence": 95 if item.get("verified") in {True, "yes"} else 82,
                    "source": source + (" (" + str(item.get("phish_detail_url")) + ")" if item.get("phish_detail_url") else ""),
                    "firstSeen": item.get("submission_time") or today(),
                    "lastSeen": item.get("verification_time") or today(),
                    "note": "Imported automatically from PhishTank verified-online feed.",
                })
            loaded = True
            print(f"PhishTank loaded: {source}")
            break
        else:
            reader = csv.DictReader(io.StringIO(text))
            count = 0
            for row in reader:
                candidate = row.get("url") or row.get("phish_url") or next((v for v in row.values() if isinstance(v, str) and v.startswith(("http://", "https://"))), "")
                if not candidate:
                    continue
                upsert(entries, {
                    "url": candidate,
                    "type": "phishing",
                    "reports": 1,
                    "confidence": 90,
                    "source": source,
                    "firstSeen": row.get("submission_time") or today(),
                    "lastSeen": row.get("verification_time") or today(),
                    "note": "Imported automatically from PhishTank public CSV feed.",
                })
                count += 1
            loaded = count > 0
            if loaded:
                print(f"PhishTank loaded: {source} ({count} rows)")
                break
    if not loaded:
        print("PhishTank skipped: public feeds unavailable/rate-limited; add PHISHTANK_APP_KEY secret for best results")

def import_urlhaus_custom(entries: dict[str, dict[str, Any]]) -> None:
    url = os.environ.get("URLHAUS_FEED_URL", "").strip()
    if not url:
        print("URLhaus/custom skipped: URLHAUS_FEED_URL secret is not set")
        return
    try:
        text = fetch_text(url)
    except Exception as exc:
        print(f"URLhaus/custom skipped: {exc}")
        return
    # Accept either URL-per-line, CSV, or quoted CSV with a URL column.
    for row in csv.reader(io.StringIO(text)):
        candidate = next((cell.strip() for cell in row if cell.strip().startswith(("http://", "https://"))), "")
        if not candidate and len(row) == 1:
            candidate = row[0].strip()
        if candidate.startswith("#"):
            continue
        upsert(entries, {
            "url": candidate,
            "type": "malware",
            "reports": 1,
            "confidence": 86,
            "source": "URLhaus/custom malware feed",
            "note": "Imported automatically from configured malware URL feed.",
        })


def issue_field(body: str, label: str) -> str:
    # GitHub issue forms render roughly as: ### Label\nvalue\n
    pattern = re.compile(rf"###\s*{re.escape(label)}\s*\n(?P<value>.*?)(?=\n###\s|\Z)", re.I | re.S)
    m = pattern.search(body or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group("value").strip())


def github_api(path: str) -> Any:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        return None
    url = f"https://api.github.com/repos/{repo}{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def import_approved_github_reports(entries: dict[str, dict[str, Any]]) -> None:
    try:
        issues = github_api("/issues?state=open&labels=approved-threat&per_page=100")
    except Exception as exc:
        print(f"Approved GitHub reports skipped: {exc}")
        return
    if not isinstance(issues, list):
        return
    for issue in issues:
        if not isinstance(issue, dict) or "pull_request" in issue:
            continue
        body = issue.get("body") or ""
        target = issue_field(body, "URL or domain") or issue.get("title", "")
        threat_type = issue_field(body, "Threat type") or "user reported threat"
        reason = issue_field(body, "Why is it dangerous?")
        proof = issue_field(body, "Source / proof link, if any")
        number = issue.get("number", "?")
        upsert(entries, {
            "url": target,
            "domain": target,
            "type": threat_type,
            "reports": 1,
            "confidence": 72,
            "source": f"Approved GitHub report #{number}" + (f"; proof: {proof}" if proof else ""),
            "note": reason or "Approved user report.",
        })


def write_relay(entries: dict[str, dict[str, Any]]) -> None:
    ordered = sorted(entries.values(), key=lambda e: (int(e.get("confidence", 0)), int(e.get("reports", 0)), e.get("lastSeen", "")), reverse=True)[:MAX_ENTRIES]
    payload = {
        "schemaVersion": 1,
        "generatedAt": now_iso(),
        "maintainer": os.environ.get("GITHUB_REPOSITORY", "hudsondiamondanimation-lab/WireShield_Relay"),
        "description": "WireShield global relay feed. Public JSON used by the browser extension and desktop app for reviewed dangerous-site updates.",
        "policy": "Trusted feeds are imported automatically. User reports require the approved-threat label before inclusion.",
        "sources": [
            "WireShield checked test entries",
            "OpenPhish community feed",
            "Optional PhishTank verified feed when PHISHTANK_APP_KEY is configured",
            "Optional URLhaus/custom feed when URLHAUS_FEED_URL is configured",
            "Approved GitHub issue reports labeled approved-threat",
        ],
        "entries": ordered,
    }
    RELAY.parent.mkdir(parents=True, exist_ok=True)
    RELAY.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")



def simple_rss_items(url: str, keywords: list[str], limit: int = 12) -> list[dict[str, Any]]:
    try:
        text = fetch_text(url)
    except Exception as exc:
        return [{"title": "Source unavailable", "source": url, "note": str(exc), "type": "source-status"}]
    items: list[dict[str, Any]] = []
    for block in re.findall(r"<item\b.*?</item>|<entry\b.*?</entry>", text, flags=re.I | re.S):
        def tag(name: str) -> str:
            m = re.search(rf"<{name}[^>]*>(.*?)</{name}>", block, flags=re.I | re.S)
            if not m:
                return ""
            return re.sub(r"<[^>]+>", " ", m.group(1)).replace("<![CDATA[", "").replace("]]>", "").strip()
        title = tag("title") or "Untitled"
        summary = tag("description") or tag("summary")
        haystack = (title + " " + summary).lower()
        if keywords and not any(k.lower() in haystack for k in keywords):
            continue
        items.append({
            "title": re.sub(r"\s+", " ", title)[:240],
            "type": "trusted-source-item",
            "source": url,
            "published": tag("pubDate") or tag("updated") or tag("published"),
            "note": re.sub(r"\s+", " ", summary)[:500],
        })
        if len(items) >= limit:
            break
    return items


def recent_breaches(limit: int = 12) -> list[dict[str, Any]]:
    try:
        data = json.loads(fetch_text("https://haveibeenpwned.com/api/v3/breaches"))
    except Exception as exc:
        return [{"title": "Have I Been Pwned unavailable", "type": "source-status", "source": "HIBP breach catalog", "note": str(exc)}]
    if not isinstance(data, list):
        return []
    out = []
    for item in sorted(data, key=lambda x: str(x.get("AddedDate", "")), reverse=True)[:limit]:
        out.append({
            "title": item.get("Title") or item.get("Name") or "Unknown breach",
            "type": "data breach",
            "source": "Have I Been Pwned breach catalog",
            "published": item.get("AddedDate") or item.get("BreachDate") or "",
            "affectedAccounts": item.get("PwnCount"),
            "note": re.sub(r"\s+", " ", str(item.get("Description") or ""))[:500],
        })
    return out


def write_intel_feed() -> None:
    items: list[dict[str, Any]] = []
    items.extend(simple_rss_items("https://consumer.ftc.gov/consumer-alerts/rss", ["scam", "phishing", "gift card", "crypto", "impersonat", "refund"], 12))
    items.extend(simple_rss_items("https://www.cisa.gov/news.xml", ["malware", "ransomware", "phishing", "vulnerab", "alert", "advisory"], 12))
    items.extend(recent_breaches(12))
    items.append({
        "title": "Data broker privacy watch",
        "type": "data broker",
        "source": "WireShield guidance",
        "published": today(),
        "note": "Recheck broker opt-out results every 30-90 days; many brokers repopulate data. Keep broker name, profile URL, date requested, and confirmation emails.",
    })
    payload = {
        "schemaVersion": 1,
        "generatedAt": now_iso(),
        "description": "WireShield trusted-intelligence relay for scams, breaches, malware/security alerts, and broker/privacy watch notes.",
        "items": items,
    }
    INTEL.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
def main() -> int:
    entries = load_existing()
    for item in SAFE_TESTS:
        upsert(entries, item)
    import_openphish(entries)
    import_phishtank(entries)
    import_urlhaus_custom(entries)
    import_approved_github_reports(entries)
    write_relay(entries)
    write_intel_feed()
    print(f"Wrote {RELAY} with {len(entries)} entries")
    print(f"Wrote {INTEL}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())




