# Incident Report — Brute Force Attack (RDP/SSH)

## Detection Summary
- **Rule Triggered:** Brute Force — Multiple Failed Login Attempts
- **Timestamp:** June 26, 2026 10:30 UTC
- **Source IP:** 192.168.1.100
- **Target User:** administrator
- **Failed Attempts:** 47 in 2 minutes
- **Alert Severity:** High

## Evidence
- **KQL Query Used:** `status: 401 | stats count by source.ip, user.name`
- **Attack Pattern:** Automated password guessing with 100-300 ms intervals
- **Wordlist Used:** Likely rockyou.txt

## MITRE ATT&CK Mapping
- **Technique ID:** T1110.001
- **Technique Name:** Brute Force: Password Guessing
- **Tactic:** Credential Access

## Indicators of Compromise (IOCs)
- **Source IP:** 192.168.1.100
- **Target Username:** administrator
- **Attack Protocol:** SSH/RDP
- **Time Window:** 10:28:15 — 10:30:47 UTC

## Recommendations
1. Block source IP 192.168.1.100 at firewall
2. Reset administrator account password
3. Enable account lockout policy
4. Implement MFA on all admin accounts

## Status
- ✅ RESOLVED — IP blocked, password reset, monitoring enabled
