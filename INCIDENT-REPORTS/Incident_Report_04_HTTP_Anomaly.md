# Incident Report — HTTP Activity Spike (Endpoint Enumeration)

## Detection Summary
- **Rule Triggered:** HTTP 4xx/5xx Status Code Anomaly
- **Timestamp:** June 26, 2026 15:20 UTC
- **HTTP Status Codes:** 404, 503
- **Error Volume:** 1,247 errors in 5 minutes
- **Source IPs:** 45 unique IPs from 203.0.113.0/24
- **Alert Severity:** Medium

## Evidence
- **KQL Query Used:** `response: "404" or response: "503"`
- **Attack Pattern:** Sequential endpoint testing
- **User-Agent:** python-requests/2.25.1 (automated scanner)
- **Endpoints Tested:** 450+ different URL paths

## MITRE ATT&CK Mapping
- **Technique:** T1190 — Exploit Public-Facing Application
- **Tactic:** Initial Access
- **Associated:** T1592 — Gather Victim Host Information

## Indicators of Compromise (IOCs)
- **Source Subnet:** 203.0.113.0/24
- **User-Agent:** python-requests/2.25.1
- **Attack Window:** 15:20:00 — 15:25:00 UTC

## Recommendations
1. Block entire 203.0.113.0/24 subnet at firewall
2. Implement rate limiting on all endpoints
3. Deploy Web Application Firewall (WAF)
4. Remove debug endpoints from production

## Status
- ✅ DETECTED — HTTP anomaly detected
- ✅ CONTAINED — Attacker subnet blocked
- ⏳ HARDENING — WAF implementation in progress
