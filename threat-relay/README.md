# WireShield threat relay

Public raw URL expected by the extension:

`https://raw.githubusercontent.com/hudsondiamondanimation-lab/WireShield/main/threat-relay/wireshield-threat-feed.json`

## Entry format

```json
{
  "domain": "bad.example",
  "url": "https://bad.example/login",
  "type": "phishing",
  "reports": 12,
  "confidence": 95,
  "source": "Reviewed user reports + trusted feed",
  "firstSeen": "2026-06-26",
  "lastSeen": "2026-06-26",
  "note": "Short human-readable reason"
}
```

Types can be `phishing`, `scam`, `malware`, `remote-access scam`, `fake shop`, or similar plain text.

## Privacy/safety rule

Do not auto-upload users' browsing history. The extension only reads this JSON and stores local user reports in the browser. Users can export their local reports and you can review/merge them here.

## Trusted source ideas

- PhishTank verified phishing data
- OpenPhish community feed
- URLhaus malware URL data, respecting their Auth-Key/rate/license requirements
- Manually reviewed user submissions
