# Incident Report — Unauthorized Privilege Escalation

## Detection Summary
- **Rule Triggered:** Privilege Escalation — User Role Elevation
- **Timestamp:** June 26, 2026 13:45 UTC
- **User Account:** john.smith@company.com
- **Role Change:** Editor → Administrator
- **Duration:** 30 seconds from login to elevation
- **Alert Severity:** High

## Evidence
- **KQL Query Used:** `http.response.status_code: 403`
- **Event Type:** Unauthorized access attempt to admin resources
- **Resources Accessed:** /admin/users, /admin/billing, /admin/systems

## MITRE ATT&CK Mapping
- **Technique:** T1548 — Abuse Elevation Control Mechanism
- **Tactic:** Privilege Escalation
- **Associated:** T1078 — Valid Accounts

## Indicators of Compromise (IOCs)
- **User Account:** john.smith@company.com
- **Endpoints Accessed:** /admin/users, /admin/billing, /admin/systems
- **Timestamp Window:** 13:45:00 — 14:30:00 UTC

## Recommendations
1. Suspend john.smith@company.com account immediately
2. Review all actions by john.smith in last 24 hours
3. Implement human approval workflow for privilege elevation
4. Enable MFA on all accounts
5. Implement just-in-time (JIT) privileged access model

## Status
- ✅ DETECTED — Privilege escalation detected
- ✅ CONTAINED — Account suspended
- ⏳ INVESTIGATION — Forensic analysis underway
  
