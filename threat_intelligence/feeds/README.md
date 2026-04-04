# Threat Intelligence Feed Formats

This directory contains cached feed files downloaded by `updater.py`.

## File Formats

### `emerging_threats.txt`
Plain-text file from [Emerging Threats](https://rules.emergingthreats.net/).

```
# Auto-generated – N entries
1.2.3.4
5.6.7.0/24
```

One IP address or CIDR block per line. Lines starting with `#` are comments.
Source URL: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`

---

### `spamhaus_drop.txt` / `spamhaus_edrop.txt`
[Spamhaus DROP](https://www.spamhaus.org/drop/) and EDROP lists.

```
; Spamhaus DROP List
1.2.3.0/24 ; SBL12345
```

Lines beginning with `;` are comments. Data lines contain a CIDR block, a
semicolon separator, and a Spamhaus Block List reference number.

---

### `ip_reputation.json`
Local cache written and read by `ThreatFeedManager`. Structure:

```json
{
  "1.2.3.4": {
    "ip": "1.2.3.4",
    "score": 0.75,
    "is_malicious": true,
    "sources": {
      "abuseipdb": 0.9,
      "spamhaus": 1.0,
      "emerging_threats": 0.0
    },
    "cached": false,
    "timestamp": 1700000000.0
  }
}
```

Entries older than `THREAT_CACHE_TTL` seconds (default 3600) are considered
stale and re-fetched on the next `check_ip()` call.

---

### Custom feeds (`custom_feed_N.txt`)
Any URLs listed in the `EXTRA_THREAT_FEEDS` environment variable (semicolon
separated) are downloaded as plain-text IP lists and written here.
