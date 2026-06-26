# Incident Report — Unauthorized Data Transfer (Possible Exfiltration)

## Detection Summary
- **Rule Triggered:** Unauthorized Data Transfer — Possible Exfiltration
- **Timestamp:** June 26, 2026 17:10 UTC
- **Data Volume:** 845 MB transferred outbound
- **Destination IP:** 198.51.100.200 (external, non-approved)
- **Duration:** 8 minutes
- **Alert Severity:** Critical

## Evidence
- **KQL Query Used:** `bytes > 500000`
- **Source:** Customer database server (db-prod-01)
- **User:** sarah.johnson@company.com
- **Normal Transfer Rate:** ~50 MB/day
- **Incident Transfer Rate:** 105 MB/minute (2,100x normal)

## MITRE ATT&CK Mapping
- **Technique:** T1030 — Data Transfer Size Limits
- **Tactic:** Exfiltration
- **Associated:** T1020 — Automated Exfiltration

## Indicators of Compromise (IOCs)
- **Source User:** sarah.johnson@company.com
- **Source System:** db-prod-01
- **Destination IP:** 198.51.100.200
- **Data Volume:** 845 MB
- **Records Affected:** 5,234 customer accounts

## Recommendations
1. Disconnect db-prod-01 from network immediately
2. Suspend sarah.johnson@company.com account
3. Block destination IP 198.51.100.200 at firewall
4. Implement Data Loss Prevention (DLP) rules
5. Enable MFA on all developer accounts
6. Notify affected customers (GDPR requirement — 72 hours)

## Status
- ✅ DETECTED — Data exfiltration detected
- ✅ CONTAINED — Database isolated, IP blocked
- ⏳ INVESTIGATION — Forensic analysis underway
- ⏳ NOTIFICATIONS — Customer breach notification pending
