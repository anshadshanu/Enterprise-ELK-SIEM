# Incident Report — SQL Injection Attack

## Detection Summary
- **Rule Triggered:** SQL Injection Attempt Detection
- **Timestamp:** June 26, 2026 11:15 UTC
- **Target URL:** /api/search?q=
- **HTTP Status:** 200 OK (successful query execution)
- **Source IP:** 203.0.113.45
- **Alert Severity:** Critical

## Evidence
- **KQL Query Used:** `url.original: (*UNION* OR *SELECT* OR *DROP*)`
- **Malicious Payload:** `q=1' UNION SELECT * FROM users--`
- **Records Exfiltrated:** ~5,000 user database records

## MITRE ATT&CK Mapping
- **Technique:** T1190 — Exploit Public-Facing Application
- **Tactic:** Initial Access

## Indicators of Compromise (IOCs)
- **Source IP:** 203.0.113.45
- **Malicious Pattern:** UNION SELECT, FROM users, -- (SQL comment)
- **Affected Endpoint:** /api/search
- **Records Compromised:** 5,234 customer accounts

## Recommendations
1. Block source IP 203.0.113.45 at firewall
2. Take /api/search endpoint offline until patched
3. Implement parameterized queries
4. Deploy Web Application Firewall (WAF)

## Status
- ✅ DETECTED — Intrusion detected and logged
- ✅ CONTAINED — Endpoint taken offline
- ⏳ REMEDIATION — Patch development underway
