#!/usr/bin/env python3
"""Update WireShield public threat and intelligence relay.

Dependency-free for GitHub Actions. It imports trusted public feeds, optional
source secrets, and reviewed GitHub issue reports, then writes:
- threat-relay/wireshield-threat-feed.json
- threat-relay/wireshield-intel-feed.json
- threat-relay/wireshield-source-log.json
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RELAY_DIR = ROOT / "threat-relay"
RELAY = RELAY_DIR / "wireshield-threat-feed.json"
INTEL = RELAY_DIR / "wireshield-intel-feed.json"
SOURCE_LOG = RELAY_DIR / "wireshield-source-log.json"
MAX_ENTRIES = 50000
USER_AGENT = "WireShield-Relay-Updater/1.2 (+https://github.com/hudsondiamondanimation-lab/WireShield_Relay)"
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
CISA_NEWS_RSS = "https://www.cisa.gov/news.xml"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
FTC_CONSUMER_ALERTS = "https://consumer.ftc.gov/consumer-alerts"
MS_UNWANTED_CRITERIA = "https://learn.microsoft.com/en-us/unified-secops/criteria"
SOURCE_EVENTS: list[dict[str, Any]] = []
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


def source_event(name: str, category: str, status: str, count: int = 0, url: str = "", note: str = "") -> None:
    SOURCE_EVENTS.append({
        "name": name,
        "category": category,
        "status": status,
        "count": int(count or 0),
        "url": url,
        "checkedAt": now_iso(),
        "note": str(note or "")[:500],
    })
    print(f"{name}: {status}" + (f" ({count})" if count else "") + (f" - {note}" if note else ""))


def fetch_text(url: str, headers: dict[str, str] | None = None, timeout: int = 35) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_json(url: str, headers: dict[str, str] | None = None, timeout: int = 35) -> Any:
    return json.loads(fetch_text(url, headers=headers, timeout=timeout))


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


def upsert(entries: dict[str, dict[str, Any]], entry: dict[str, Any]) -> bool:
    host = key_for(entry)
    if not host:
        return False
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
    return True


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
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if upsert(entries, {"url": line, "type": "phishing", "reports": 1, "confidence": 78, "source": "OpenPhish community feed", "note": "Imported automatically from OpenPhish community feed."}):
                count += 1
        source_event("OpenPhish community feed", "scam/phishing", "ok", count, OPENPHISH_URL, "Public phishing URL feed imported.")
    except Exception as exc:
        source_event("OpenPhish community feed", "scam/phishing", "failed", 0, OPENPHISH_URL, str(exc))


def import_phishtank(entries: dict[str, dict[str, Any]]) -> None:
    key = os.environ.get("PHISHTANK_APP_KEY", "").strip()
    candidates: list[tuple[str, str, str]] = []
    if key:
        candidates.append((f"https://data.phishtank.com/data/{urllib.parse.quote(key)}/online-valid.json", "json", "PhishTank verified keyed feed"))
    candidates.extend([
        ("https://data.phishtank.com/data/online-valid.json", "json", "PhishTank public verified feed"),
        ("https://data.phishtank.com/data/online-valid.csv", "csv", "PhishTank public verified feed"),
    ])
    notes = []
    for url, fmt, source in candidates:
        try:
            text = fetch_text(url)
            count = 0
            if fmt == "json":
                data = json.loads(text)
                if not isinstance(data, list):
                    raise ValueError("JSON root was not a list")
                for item in data:
                    if isinstance(item, dict) and item.get("url"):
                        if upsert(entries, {"url": item.get("url"), "type": "phishing", "reports": 1, "confidence": 95 if item.get("verified") in {True, "yes"} else 82, "source": source + (" (" + str(item.get("phish_detail_url")) + ")" if item.get("phish_detail_url") else ""), "firstSeen": item.get("submission_time") or today(), "lastSeen": item.get("verification_time") or today(), "note": "Imported automatically from PhishTank verified-online feed."}):
                            count += 1
            else:
                reader = csv.DictReader(io.StringIO(text))
                for row in reader:
                    candidate = row.get("url") or row.get("phish_url") or next((v for v in row.values() if isinstance(v, str) and v.startswith(("http://", "https://"))), "")
                    if candidate and upsert(entries, {"url": candidate, "type": "phishing", "reports": 1, "confidence": 90, "source": source, "firstSeen": row.get("submission_time") or today(), "lastSeen": row.get("verification_time") or today(), "note": "Imported automatically from PhishTank public CSV feed."}):
                        count += 1
            source_event(source, "scam/phishing", "ok", count, url, "PhishTank verified-online phishing database imported.")
            return
        except urllib.error.HTTPError as exc:
            notes.append(f"{url}: HTTP {exc.code}")
        except Exception as exc:
            notes.append(f"{url}: {exc}")
    source_event("PhishTank", "scam/phishing", "failed", 0, "https://www.phishtank.com/developer_info.php", "; ".join(notes)[:500] or "No public feed loaded; app key recommended.")


def import_urlhaus(entries: dict[str, dict[str, Any]]) -> None:
    candidates: list[tuple[str, str]] = []
    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    custom = os.environ.get("URLHAUS_FEED_URL", "").strip()
    if custom:
        candidates.append((custom, "URLhaus/custom malware feed"))
    if auth_key:
        candidates.extend([
            (f"https://urlhaus-api.abuse.ch/v2/files/exports/{urllib.parse.quote(auth_key)}/recent.csv", "URLhaus authenticated recent malware CSV"),
            (f"https://urlhaus-api.abuse.ch/v2/files/exports/{urllib.parse.quote(auth_key)}/urls.txt", "URLhaus authenticated URL list"),
        ])
    # Older/public endpoints are tried because some deployments still allow them; failures are logged cleanly.
    candidates.extend([
        ("https://urlhaus.abuse.ch/downloads/csv_recent/", "URLhaus public recent CSV"),
        ("https://urlhaus.abuse.ch/downloads/text_recent/", "URLhaus public recent text"),
        ("https://urlhaus.abuse.ch/downloads/hostfile/", "URLhaus public hostfile"),
    ])
    notes = []
    for url, source in candidates:
        try:
            text = fetch_text(url)
            count = 0
            for row in csv.reader(io.StringIO(text)):
                joined = ",".join(row).strip()
                if not joined or joined.startswith("#"):
                    continue
                candidate = next((cell.strip().strip('"') for cell in row if cell.strip().startswith(("http://", "https://"))), "")
                if not candidate and len(row) == 1 and row[0].strip().startswith(("http://", "https://")):
                    candidate = row[0].strip()
                if not candidate and "0.0.0.0" in joined:
                    parts = joined.split()
                    candidate = next((p for p in parts if "." in p and not re.match(r"\d+\.\d+\.\d+\.\d+", p)), "")
                if candidate and upsert(entries, {"url": candidate, "domain": candidate, "type": "malware", "reports": 1, "confidence": 86, "source": source, "note": "Imported automatically from URLhaus malware URL/domain data."}):
                    count += 1
            if count:
                source_event(source, "malware", "ok", count, url, "URLhaus malware URL/domain data imported.")
                return
            notes.append(f"{url}: no parseable entries")
        except urllib.error.HTTPError as exc:
            notes.append(f"{url}: HTTP {exc.code}")
        except Exception as exc:
            notes.append(f"{url}: {exc}")
    source_event("URLhaus malware feeds", "malware", "skipped", 0, "https://urlhaus.abuse.ch/api/", "; ".join(notes)[:500] or "URLhaus auth key/feed not configured.")


def issue_field(body: str, label: str) -> str:
    pattern = re.compile(rf"###\s*{re.escape(label)}\s*\n(?P<value>.*?)(?=\n###\s|\Z)", re.I | re.S)
    m = pattern.search(body or "")
    return re.sub(r"\s+", " ", m.group("value").strip()) if m else ""


def github_api(path: str) -> Any:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        return None
    url = f"https://api.github.com/repos/{repo}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def import_approved_github_reports(entries: dict[str, dict[str, Any]]) -> None:
    try:
        issues = github_api("/issues?state=open&labels=approved-threat&per_page=100")
    except Exception as exc:
        source_event("Approved GitHub reports", "user reports", "failed", 0, "GitHub API", str(exc))
        return
    if not isinstance(issues, list):
        source_event("Approved GitHub reports", "user reports", "skipped", 0, "GitHub API", "GITHUB_TOKEN/GITHUB_REPOSITORY unavailable outside Actions.")
        return
    count = 0
    for issue in issues:
        if not isinstance(issue, dict) or "pull_request" in issue:
            continue
        body = issue.get("body") or ""
        target = issue_field(body, "URL or domain") or issue.get("title", "")
        threat_type = issue_field(body, "Threat type") or "user reported threat"
        reason = issue_field(body, "Why is it dangerous?")
        proof = issue_field(body, "Source / proof link, if any")
        number = issue.get("number", "?")
        if upsert(entries, {"url": target, "domain": target, "type": threat_type, "reports": 1, "confidence": 72, "source": f"Approved GitHub report #{number}" + (f"; proof: {proof}" if proof else ""), "note": reason or "Approved user report."}):
            count += 1
    source_event("Approved GitHub reports", "user reports", "ok", count, "GitHub API", "Only issues labeled approved-threat are added to the global feed.")


def simple_rss_items(url: str, keywords: list[str], limit: int = 12, source_name: str | None = None) -> list[dict[str, Any]]:
    try:
        text = fetch_text(url)
    except Exception as exc:
        source_event(source_name or url, "intel/rss", "failed", 0, url, str(exc))
        return [{"title": "Source unavailable", "source": source_name or url, "url": url, "note": str(exc), "type": "source-status", "published": today()}]
    items: list[dict[str, Any]] = []
    for block in re.findall(r"<item\b.*?</item>|<entry\b.*?</entry>", text, flags=re.I | re.S):
        def tag(name: str) -> str:
            m = re.search(rf"<{name}[^>]*>(.*?)</{name}>", block, flags=re.I | re.S)
            if not m:
                return ""
            return re.sub(r"<[^>]+>", " ", m.group(1)).replace("<![CDATA[", "").replace("]]>", "").strip()
        title = re.sub(r"\s+", " ", tag("title") or "Untitled")[:240]
        summary = re.sub(r"\s+", " ", tag("description") or tag("summary"))[:500]
        haystack = (title + " " + summary).lower()
        if keywords and not any(k.lower() in haystack for k in keywords):
            continue
        items.append({"title": title, "type": "trusted-source-item", "source": source_name or url, "url": url, "published": tag("pubDate") or tag("updated") or tag("published"), "note": summary})
        if len(items) >= limit:
            break
    source_event(source_name or url, "intel/rss", "ok", len(items), url, "RSS/news items imported.")
    return items


def ftc_consumer_alert_items(limit: int = 10) -> list[dict[str, Any]]:
    try:
        html = fetch_text(FTC_CONSUMER_ALERTS)
    except Exception as exc:
        source_event("FTC consumer alerts", "scams", "failed", 0, FTC_CONSUMER_ALERTS, str(exc))
        return [{"title": "FTC consumer alerts unavailable", "type": "source-status", "source": "FTC consumer alerts", "url": FTC_CONSUMER_ALERTS, "published": today(), "note": str(exc)}]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for href, text in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, flags=re.I | re.S):
        title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()
        if len(title) < 12 or title.lower() in seen:
            continue
        if not any(k in title.lower() for k in ["scam", "fraud", "phishing", "alert", "imposter", "imperson", "crypto", "gift", "hack", "breach"]):
            continue
        seen.add(title.lower())
        url = urllib.parse.urljoin(FTC_CONSUMER_ALERTS, href)
        rows.append({"title": title[:240], "type": "scam / consumer alert", "source": "FTC consumer alerts", "url": url, "published": today(), "note": "FTC consumer alert item collected from the public consumer alerts page."})
        if len(rows) >= limit:
            break
    source_event("FTC consumer alerts", "scams", "ok", len(rows), FTC_CONSUMER_ALERTS, "Consumer scam alert page parsed.")
    return rows


def cisa_kev_items(limit: int = 15) -> list[dict[str, Any]]:
    try:
        data = fetch_json(CISA_KEV_JSON)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    except Exception as exc:
        source_event("CISA Known Exploited Vulnerabilities", "hacks/vulnerabilities", "failed", 0, CISA_KEV_JSON, str(exc))
        return [{"title": "CISA KEV unavailable", "type": "source-status", "source": "CISA KEV", "url": CISA_KEV_JSON, "published": today(), "note": str(exc)}]
    sorted_vulns = sorted(vulns, key=lambda x: str(x.get("dateAdded", "")), reverse=True)[:limit]
    out = []
    for v in sorted_vulns:
        cve = v.get("cveID") or "CVE"
        vendor = v.get("vendorProject") or "unknown vendor"
        product = v.get("product") or "unknown product"
        out.append({"title": f"{cve}: exploited vulnerability in {vendor} {product}", "type": "known exploited vulnerability / hack risk", "source": "CISA Known Exploited Vulnerabilities catalog", "url": CISA_KEV_JSON, "published": v.get("dateAdded") or today(), "note": (v.get("shortDescription") or v.get("requiredAction") or "Known exploited vulnerability listed by CISA.")[:500]})
    source_event("CISA Known Exploited Vulnerabilities", "hacks/vulnerabilities", "ok", len(out), CISA_KEV_JSON, "Recent exploited vulnerabilities imported.")
    return out


def nvd_recent_items(limit: int = 12) -> list[dict[str, Any]]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    params = urllib.parse.urlencode({
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "cvssV3Severity": "CRITICAL",
        "noRejected": "",
        "resultsPerPage": str(limit),
    })
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + params
    try:
        data = fetch_json(url)
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    except Exception as exc:
        source_event("NVD CVE API", "hacks/vulnerabilities", "failed", 0, "https://services.nvd.nist.gov/rest/json/cves/2.0", str(exc))
        return [{"title": "NVD CVE API unavailable", "type": "source-status", "source": "NVD CVE API", "url": "https://nvd.nist.gov/developers/vulnerabilities", "published": today(), "note": str(exc)}]
    out = []
    for row in vulns[:limit]:
        cve = row.get("cve", {}) if isinstance(row, dict) else {}
        cve_id = cve.get("id", "CVE")
        descs = cve.get("descriptions", [])
        desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "") if isinstance(descs, list) else ""
        out.append({"title": f"{cve_id}: recently changed critical CVE", "type": "critical vulnerability / hack risk", "source": "NVD CVE API", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "published": cve.get("lastModified") or cve.get("published") or today(), "note": desc[:500]})
    source_event("NVD CVE API", "hacks/vulnerabilities", "ok", len(out), "https://services.nvd.nist.gov/rest/json/cves/2.0", "Recent critical CVEs imported.")
    return out


def recent_breaches(limit: int = 12) -> list[dict[str, Any]]:
    try:
        data = fetch_json(HIBP_BREACHES)
    except Exception as exc:
        source_event("Have I Been Pwned breach catalog", "data breaches", "failed", 0, HIBP_BREACHES, str(exc))
        return [{"title": "Have I Been Pwned unavailable", "type": "source-status", "source": "HIBP breach catalog", "url": HIBP_BREACHES, "published": today(), "note": str(exc)}]
    if not isinstance(data, list):
        source_event("Have I Been Pwned breach catalog", "data breaches", "failed", 0, HIBP_BREACHES, "Unexpected response format.")
        return []
    out = []
    for item in sorted(data, key=lambda x: str(x.get("AddedDate", "")), reverse=True)[:limit]:
        out.append({"title": item.get("Title") or item.get("Name") or "Unknown breach", "type": "data breach", "source": "Have I Been Pwned breach catalog", "url": HIBP_BREACHES, "published": item.get("AddedDate") or item.get("BreachDate") or "", "affectedAccounts": item.get("PwnCount"), "note": re.sub(r"\s+", " ", str(item.get("Description") or ""))[:500]})
    source_event("Have I Been Pwned breach catalog", "data breaches", "ok", len(out), HIBP_BREACHES, "Recent breach catalog items imported.")
    return out


def static_guidance_items() -> list[dict[str, Any]]:
    items = [
        {"title": "Data broker privacy watch", "type": "data broker / privacy", "source": "WireShield guidance", "url": FTC_CONSUMER_ALERTS, "published": today(), "note": "Recheck broker opt-out results every 30-90 days; many brokers repopulate data. Keep broker name, profile URL, date requested, and confirmation emails."},
        {"title": "Unwanted software / bloatware watch", "type": "bloatware / potentially unwanted software", "source": "Microsoft unwanted software evaluation criteria", "url": MS_UNWANTED_CRITERIA, "published": today(), "note": "Watch for software that changes browser settings, injects ads, bundles unwanted offers, hides removal paths, exaggerates cleanup claims, or uses misleading install prompts."},
        {"title": "Remote-access scam reminder", "type": "remote-access scam", "source": "WireShield guidance from FTC/CISA-style scam prevention", "url": FTC_CONSUMER_ALERTS, "published": today(), "note": "Treat unexpected requests to install AnyDesk, TeamViewer, UltraViewer, RustDesk, or ScreenConnect as high risk, especially when paired with refunds, bank warnings, crypto, or gift cards."},
    ]
    source_event("WireShield static guidance", "guidance", "ok", len(items), "local", "Data broker, bloatware, and scam safety guidance added.")
    return items


def write_relay(entries: dict[str, dict[str, Any]]) -> None:
    ordered = sorted(entries.values(), key=lambda e: (int(e.get("confidence", 0)), int(e.get("reports", 0)), e.get("lastSeen", "")), reverse=True)[:MAX_ENTRIES]
    payload = {
        "schemaVersion": 2,
        "generatedAt": now_iso(),
        "maintainer": os.environ.get("GITHUB_REPOSITORY", "hudsondiamondanimation-lab/WireShield_Relay"),
        "description": "WireShield global relay feed. Public JSON used by the browser extension and desktop app for reviewed dangerous-site updates.",
        "policy": "Trusted feeds are imported automatically. User reports require the approved-threat label before inclusion.",
        "sources": [event for event in SOURCE_EVENTS if event.get("category") in {"scam/phishing", "malware", "user reports"}],
        "entries": ordered,
    }
    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    RELAY.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_intel_feed() -> None:
    items: list[dict[str, Any]] = []
    items.extend(ftc_consumer_alert_items(10))
    items.extend(simple_rss_items(CISA_NEWS_RSS, ["malware", "ransomware", "phishing", "vulnerab", "alert", "advisory", "exploit"], 12, "CISA news feed"))
    items.extend(cisa_kev_items(15))
    items.extend(nvd_recent_items(12))
    items.extend(recent_breaches(12))
    items.extend(static_guidance_items())
    payload = {
        "schemaVersion": 2,
        "generatedAt": now_iso(),
        "description": "WireShield trusted-intelligence relay for scams, hacks, exploited vulnerabilities, breaches, malware, data brokers, and unwanted software.",
        "sources": SOURCE_EVENTS,
        "items": items,
    }
    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    INTEL.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_source_log() -> None:
    payload = {
        "schemaVersion": 1,
        "generatedAt": now_iso(),
        "refreshPolicy": "GitHub Actions updates the relay about every 10 minutes. Individual sources may be hourly, 5-minute, keyed, or rate-limited depending on their published rules.",
        "sources": SOURCE_EVENTS,
    }
    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_LOG.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    entries = load_existing()
    for item in SAFE_TESTS:
        upsert(entries, item)
    source_event("WireShield checked test entries", "scam/phishing", "ok", len(SAFE_TESTS), "https://testsafebrowsing.appspot.com/", "Safe test-only block page entries added.")
    import_openphish(entries)
    import_phishtank(entries)
    import_urlhaus(entries)
    import_approved_github_reports(entries)
    write_intel_feed()
    write_relay(entries)
    write_source_log()
    print(f"Wrote {RELAY} with {len(entries)} tracked domains before cap")
    print(f"Wrote {INTEL}")
    print(f"Wrote {SOURCE_LOG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
