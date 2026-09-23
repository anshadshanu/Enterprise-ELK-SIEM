# Incident Report #7 — Suspicious Encoded PowerShell Execution

## Detection Summary
- **Rule Triggered:** Execution: Suspicious Encoded PowerShell Execution
- **Timestamp:** Synthetic Test — June 26, 2026 17:50 UTC
- **Source Host:** WIN-G0HL1ICTS2B (Windows Server 2022)
- **Process:** powershell.exe
- **Command Line:** Encoded Base64 payload
- **Alert Severity:** Medium
- **Risk Score:** 50

## Evidence
- **Detection Rule:** EQL Rule 2 (T1059.001)
- **Event Code:** Sysmon Event ID 1 (Process Creation)
- **Process Name:** `powershell.exe`
- **Command Line:** `powershell.exe -enc V3JpdGUtSG9zdCAnU3ludGhldGljIFNvYyBMYWIgQWxlcnQgVGVzdCc=`
- **Encoding Flag:** `-enc` (Base64 encoded command)
- **Decoded Payload:** `Write-Host 'Synthetic Soc Lab Alert Test'`
- **Parent Process:** cmd.exe
- **Execution Context:** Administrator privilege level
- **Detection Latency:** 5 seconds from execution to alert

## Investigation Process
1. Sysmon Event ID 1 captured process creation of powershell.exe
2. Command-line argument analysis detected suspicious encoding flag (`-enc`)
3. EQL rule matched on PowerShell + encoding parameter combination
4. Alert fired immediately upon pattern match
5. Winlogbeat transmitted event to Elasticsearch within 2 seconds
6. Kibana Alert Dashboard populated alert with full context
7. SOAR webhook triggered for automated response

## Attack Details
**Encoded PowerShell Obfuscation:**

PowerShell encoding is one of the most common evasion techniques used by malware and penetration testing tools. By encoding scripts in Base64, attackers can bypass content-based detection and user scrutiny.

**Why Encoding is Dangerous:**
- Bypasses string-matching signatures
- Hides malicious intent from manual inspection
- Easy to decode and execute on target
- Commonly used in malware delivery (emotet, trickbot, cobalt strike)
- Legitimate usage is extremely rare

**Attack Chain:**
1. Attacker crafts malicious PowerShell script
2. Encodes script in Base64 to evade detection
3. Executes via `powershell.exe -enc [base64_payload]`
4. Payload automatically decodes and executes
5. Malicious actions occur (ransomware, credential theft, lateral movement)

## MITRE ATT&CK Mapping
- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Tactic:** Execution
- **Adversary Goal:** Execute malicious code while evading detection

## Indicators of Compromise (IOCs)
- **Process Name:** powershell.exe
- **Encoding Flag:** `-enc`, `-encodedcommand`, or `-e`
- **Encoded Payload:** V3JpdGUtSG9zdCAnU3ludGhldGljIFNvYyBMYWIgQWxlcnQgVGVzdCc=
- **Decoded Content:** Write-Host 'Synthetic Soc Lab Alert Test'
- **Parent Process:** cmd.exe
- **Execution Timestamp:** [from Sysmon event]

## Root Cause Analysis
**Vulnerability:** PowerShell `-enc` parameter allows arbitrary command execution with encoding obfuscation

**Why Encoding Works as Evasion:**
- Content-based detection misses encoded payloads
- Static analysis cannot decode without execution
- Users may not inspect encoded commands
- Encoding is legitimate for certain scripts, creating detection ambiguity
- Extremely common in malware delivery chains

## Detection Strength
✅ **Rule Accuracy:** High (encoded PowerShell is rarely legitimate)
✅ **Detection Method:** EQL pattern matching on command-line arguments
✅ **Response Speed:** 5 seconds from execution to alert
✅ **Alert Confidence:** Medium-High (some false positives possible on legitimate usage)

## Decoded Payload Analysis

**Encoded:** `V3JpdGUtSG9zdCAnU3ludGhldGljIFNvYyBMYWIgQWxlcnQgVGVzdCc=`

**Decoded:** `Write-Host 'Synthetic Soc Lab Alert Test'`

**Assessment:** In this synthetic test, the payload is benign (Write-Host output). In real attacks, this could be:
- Credential theft (Get-Process, Get-Credential)
- Lateral movement (Invoke-Command, Enter-PSSession)
- Ransomware deployment (Download-File, Invoke-Encryption)
- Data exfiltration (Export-Csv, Send-WebRequest)

## Recommendations (Priority Order)

**IMMEDIATE (0-1 hour):**
1. Review PowerShell Execution Logs for past 24 hours on WIN-G0HL1ICTS2B
2. Decode the Base64 payload and verify legitimacy
3. Check for lateral movement or credential access attempts post-execution
4. Review all parent processes that spawned powershell.exe

**URGENT (1-24 hours):**
1. Enable PowerShell ScriptBlock Logging on all Windows servers
2. Block encoding flags via PowerShell execution policy (AllSigned)
3. Implement Windows Defender Application Guard to sandbox PowerShell
4. Deploy AMSI (Antimalware Scan Interface) hooks for payload inspection

**SHORT-TERM (1-7 days):**
1. Review and whitelist legitimate encoded PowerShell usage
2. Implement behavioral analysis to distinguish malicious from legitimate scripts
3. Deploy additional EDR detection for PowerShell process execution
4. Create inventory of all PowerShell execution methods used in organization

**LONG-TERM (1-3 months):**
1. Transition to PowerShell 7+ with built-in security improvements
2. Implement constrained language mode for unprivileged users
3. Deploy privileged access workstations (PAWs) for admin PowerShell usage
4. Conduct PowerShell security hardening across all Windows infrastructure

## Impact Assessment
- **Severity:** Medium
- **Business Impact:** Potential malware delivery and lateral movement
- **Systems at Risk:** All systems where powershell.exe is executable
- **Financial Impact:** Depends on scope of infection

## Status
- ✅ **DETECTED** — Synthetic attack successfully detected by EQL rule
- ✅ **ALERT FIRED** — Alert populated Elastic Security dashboard in real-time
- ✅ **SOAR INTEGRATION** — Webhook payload sent to orchestration platform
- ✅ **VALIDATION COMPLETE** — Rule effectiveness verified
