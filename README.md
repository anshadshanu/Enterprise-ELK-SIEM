# Enterprise Security Monitoring & Detection Engineering Platform — ELK Stack

![Kibana](https://img.shields.io/badge/Kibana-8.5.0-blue)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.5.0-green)
![Sysmon](https://img.shields.io/badge/Endpoint-Sysmon_v15-red)
![Winlogbeat](https://img.shields.io/badge/Forwarder-Winlogbeat_8.5.0-orange)
![Detection Rules](https://img.shields.io/badge/Detection%20Rules-7_Active-purple)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-yellow)
![SOAR](https://img.shields.io/badge/SOAR-Webhook_Automation-brightgreen)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## Executive Overview

This project demonstrates a production-grade **Security Operations Center (SOC) and Detection Engineering Platform** implemented across a virtualized enterprise network. The platform pairs high-volume web application security monitoring with an end-to-end **Endpoint Detection and Response (EDR) pipeline**.

Moving beyond standard log ingestion, this implementation covers the complete detection engineering lifecycle:
- **Telemetry Engineering:** Deploying kernel and user-space instrumentation via Microsoft Sysmon and Winlogbeat with authenticated TLS transport.
- **Normalization:** Mapping raw endpoint telemetry and web server activity into the **Elastic Common Schema (ECS)**.
- **Detection Engineering:** Formulating stateful **Event Query Language (EQL)** correlation rules and **Kibana Query Language (KQL)** threshold queries mapped directly to the **MITRE ATT&CK** matrix.
- **Adversary Emulation:** Simulating living-off-the-land (LotL) execution and credential access techniques to validate rule fidelity.
- **Alert Triage & SOAR Dispatch:** Routing real-time detections through an automated Webhook connector for external response orchestration.
- **Incident Response Documentation:** Delivering formal incident reports containing root-cause analysis, Indicators of Compromise (IOCs), and remediation playbooks.

---

## Architecture Pipeline

```text
  ┌────────────────────────────────────────────────────────┐
  │                 Telemetry Sources                      │
  ├────────────────────────────┬───────────────────────────┤
  │   Windows Server 2022      │   Application / Web Logs  │
  │   - Sysmon (SwiftOnSec)    │   - 14,000+ Sample Events │
  │   - Security & System Logs │   - HTTP Access / Errors  │
  └─────────────┬──────────────┴─────────────┬─────────────┘
                │                            │
                ▼ (Authenticated TLS: 9200)  ▼
  ┌────────────────────────────────────────────────────────┐
  │                 Winlogbeat 8.5.0 Shipper               │
  │            (Elastic Common Schema - ECS Mapped)        │
  └────────────────────────────┬───────────────────────────┘
                               │
                               ▼
  ┌────────────────────────────────────────────────────────┐
  │              Elasticsearch Cluster (8.5.0)             │
  │       - Distributed Indexing & Ingestion Pipelines     │
  │       - EQL Stateful Stream & Correlation Engine       │
  └────────────────────────────┬───────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
┌────────────────────────┐             ┌────────────────────────┐
│     Kibana SIEM        │             │  Elastic Security      │
│  - Threat Dashboards   │             │  - 7 Active Rules      │
│  - KQL Threat Hunting  │             │  - MITRE ATT&CK Engine │
└───────────┬────────────┘             └───────────┬────────────┘
            │                                      │
            │ (Real-Time Ingestion)                │ (Alerts Fired)
            ▼                                      ▼
┌────────────────────────┐             ┌────────────────────────┐
│   SOC Incident Triage  │             │   Automated SOAR       │
│ - 5 Structured Reports │             │ - Webhook Action       │
│ - IOC Playbooks        │             │ - JSON Alert Payload   │
└────────────────────────┘             └────────────────────────┘

Infrastructure SpecificationsComponentPlatform / HostIP / ConfigurationRole in PipelineElasticsearchUbuntu Server 22.04 LTS192.168.52.144:9200Encrypted storage, indexing, and EQL search engineKibanaUbuntu Server 22.04 LTS192.168.52.144:5601Visualization, detection rule engine, alert managementSysmonWindows Server 2022Modular SwiftOnSecurity XMLEndpoint sensor (Process Create EID 1, Handle Access)WinlogbeatWindows Server 2022v8.5.0 (Local Service)TLS log shipper forwarding operational telemetryAttack HostWindows Server 2022Local Admin ConsoleAdversary simulation & execution platformPhase 1: Endpoint Telemetry Pipeline (Sysmon & Winlogbeat)To obtain deep endpoint process introspection, Microsoft Sysmon was deployed on the Windows Server endpoint utilizing the community-standard SwiftOnSecurity schema.Sensor Verification: Verified that Microsoft-Windows-Sysmon/Operational successfully captures granular execution telemetry, specifically process creations (Event ID 1).Shipper Configuration & TLS Validation: Configured winlogbeat.yml to securely stream Sysmon operational logs to Elasticsearch over port 9200. Validated pipeline configuration and TLS handshakes using Winlogbeat diagnostics:PowerShell.\winlogbeat.exe test config
.\winlogbeat.exe test output
Ingestion & ECS Normalization: Verified live Sysmon telemetry ingestion in Kibana Discover under the winlogbeat-* data stream pattern, confirming proper field parsing for process.command_line, process.executable, winlog.event_data.ParentImage, and event.code.Phase 2: Detection Engineering & MITRE ATT&CK MappingCustom correlation rules were authored to detect adversary tradecraft across both endpoint behaviors and web applications:Active Detection Rules SummaryRule NameQuery LanguageLogic / Query DefinitionMITRE ATT&CKSeverityRisk ScoreSuspicious LSASS Process AccessEQLprocess where event.code == "1" and process.command_line : ("*rundll32*comsvcs*MiniDump*", "*procdump*", "*mimikatz*", "*sekurlsa*")Credential Access (T1003.001)High73Suspicious Encoded PowerShellEQLprocess where event.code == "1" and process.name : ("powershell.exe", "pwsh.exe") and process.command_line : ("*-enc*", "*-encodedcommand*", "*-e *", "*FromBase64String*")Execution (T1059.001)Medium50SQL Injection AttemptKQLurl.original: (*UNION* or *SELECT*)Initial Access (T1190)Critical99Data ExfiltrationKQLbytes > 500000Exfiltration (T1030)Critical99Brute Force DetectionKQLhttp.response.status_code: 401Credential Access (T1110.001)High73Privilege EscalationKQLhttp.response.status_code: 403Privilege Escalation (T1548)High73HTTP 4xx/5xx AnomaliesKQLhttp.response.status_code >= 400Initial Access (T1190)Medium47Phase 3: Adversary Emulation & Alert ValidationTo validate detection accuracy and ensure rules fire without false negatives, synthetic adversary commands were executed directly on the Windows Server endpoint:1. Living-off-the-Land LSASS Memory Dumping (T1003.001)PowerShellcmd.exe /c "rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 1234 C:\temp\test.dmp full"
Detects attempts to leverage native Windows binaries (comsvcs.dll) to dump process memory.2. Base64 Encoded PowerShell Execution (T1059.001)PowerShellpowershell.exe -enc V3JpdGUtSG9zdCAnU3ludGhldGljIFNvYyBMYWIgQWxlcnQgVGVzdCc=
Detects execution attempts masking command-line arguments behind obfuscated Base64 strings.SIEM Detection VerificationWithin 60 seconds of execution, both attack paths were correlated by the Elasticsearch rule engine, generating High and Medium security alerts in the Elastic Security dashboard:Phase 4: SOAR Webhook AutomationTo support automated incident response workflows, an external Webhook Connector (SOAR-Webhook-Dispatch) was established within Elastic Stack Management. Detection rules dispatch automated HTTP POST notifications upon alert generation:Automated Alert Payload SchemaJSON{
  "alert_name": "{{{rule.name}}}",
  "severity": "{{{rule.severity}}}",
  "risk_score": "{{{rule.risk_score}}}",
  "description": "{{{rule.description}}}",
  "host": "{{{host.name}}}",
  "timestamp": "{{{@timestamp}}}"
}
Phase 5: Threat Hunting & Visual AnalyticsKQL Threat Hunting LibraryPre-built hunting queries designed for rapid triage in Kibana Discover:Failed Authentication Surges: response: "404" or response: "503"SQL Injection Recon: url.original: (*UNION* or *SELECT*)Suspicious Outbound Volume: bytes > 10000Targeted Scanning Identification: response: "404"High-Bandwidth Data Exfiltration: bytes > 500000Security Operations DashboardsProvides real-time visibility into traffic anomalies, geographic origin threats, and status code spikes:Phase 6: Formal SOC Incident Investigation ReportsFive comprehensive incident reports were authored following standard SOC triage workflows (Detection, Log Evidence, MITRE Mapping, Root Cause, IOCs, and Remediation Playbooks):Report RefIncident NamePrimary MITRE TechniqueIncident SeverityRemediation TimelineIR-01Authentication Brute ForceT1110.001 (Password Guessing)HighImmediate IP ban; rate limitingIR-02Web SQL Injection AttemptT1190 (Exploit Public App)CriticalWAF rule update; parameter bindingIR-03Unauthorized Role AccessT1548 (Abuse Elevation)HighSession termination; RBAC reviewIR-04Vulnerability Scanning / 4xx SpikeT1190 (Exploit Public App)MediumIngress firewall blockIR-05Sensitive Data ExfiltrationT1030 (Data Transfer Size)CriticalHost isolation; egress filteringRepository StructurePlaintextEnterprise-ELK-SIEM/
├── README.md
├── screenshots/
│   ├── 01_sysmon_event_viewer.png
│   ├── 02_winlogbeat_test_ok.png
│   ├── 03_kibana_sysmon_discovery.png
│   ├── 04_elastic_detection_rules.png
│   ├── 05_elastic_security_alerts.png
│   └── 06_soar_webhook_connector.png
├── Screenshots/
│   ├── 09_rule_1_http_anomaly.png
│   ├── 14_query_1_failed_auth.png
│   ├── 19_dashboard_1_security_overview.png
│   ├── 20_dashboard_2_attack_detection.png
│   └── 22_incident_report_1_brute_force.png
└── INCIDENT-REPORTS/
    ├── Incident_Report_01_Brute_Force.md
    ├── Incident_Report_02_SQL_Injection.md
    ├── Incident_Report_03_Privilege_Escalation.md
    ├── Incident_Report_04_HTTP_Anomaly.md
    └── Incident_Report_05_Data_Exfiltration.md
AuthorMuhammed Anshad VCertified SOC Analyst (EC-Council CSA v2) | Certified IT Infrastructure & Cyber SOC Analyst (CICSA)LinkedIn: linkedin.com/in/muhemmedanshadGitHub: github.com/anshadshanu   Email: mhd.anshad.v@gmail.com
