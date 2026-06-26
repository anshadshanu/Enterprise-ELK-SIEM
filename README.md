# Enterprise Security Monitoring & Detection Platform — ELK Stack

![Kibana](https://img.shields.io/badge/Kibana-8.5-blue)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.5-green)
![Logstash](https://img.shields.io/badge/Logstash-8.5-orange)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Rules](https://img.shields.io/badge/Detection%20Rules-5-red)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-yellow)

---

## Overview

This project demonstrates a **production-grade Security Information and Event Management (SIEM)** system built using the ELK Stack (Elasticsearch, Logstash, Kibana). The goal was to simulate a real enterprise SOC environment — building detection rules, investigating security events, creating executive dashboards, and writing professional incident response reports.

This is not just a tool installation project. Every phase mirrors what a real SOC analyst does daily:
- Writing detection logic to catch attacks
- Using KQL to hunt for threats in log data
- Investigating alerts and tracing attack paths
- Documenting findings in professional incident reports
- Presenting security posture to stakeholders via dashboards

---

## Architecture

┌─────────────────────────────────────┐

│         Security Events             │

│  (Web logs, HTTP requests, errors)  │

└────────────────┬────────────────────┘

│

▼

┌───────────────────────┐

│     Elasticsearch     │

│  (Log Storage/Index)  │

└───────────┬───────────┘

│

┌───────────┴──────────┐

▼                      ▼

┌──────────┐          ┌─────────────┐

│  Kibana  │          │  Detection  │

│Dashboards│          │  Rules (5)  │

└──────────┘          └─────────────┘

│                  │

└────────┬─────────┘

▼

┌────────────────────────┐

│   Incident Reports &   │

│     Investigation      │

└────────────────────────┘

---

## Environment Setup

| Component | Version | Role |
|-----------|---------|------|
| Elasticsearch | 8.5.0 | Log storage, indexing, search engine |
| Kibana | 8.5.0 | Visualization, dashboards, SIEM rules |
| Logstash | 8.5.0 | Log ingestion and processing pipeline |
| Ubuntu Server | 22.04 | ELK Stack host |
| Windows Server | 2022 | Browser access and monitoring client |

**How it was set up:**
- ELK Stack installed on Ubuntu Server VM running on VMware Workstation
- Kibana configured with encryption key for Security module access
- Kibana Sample Web Logs loaded as the primary data source (14,000+ realistic web traffic events)
- Windows Server 2022 used to access Kibana via browser at `http://192.168.52.144:5601`

---

## Security Dashboard

The Kibana dashboard provides real-time visibility into web traffic, error rates, geographic distribution of requests, and HTTP response code anomalies.

![Security Dashboard](Screenshots/19_dashboard_1_security_overview.png)

**What this shows:**
- 1,824 total visits with 841 unique visitors
- HTTP 4xx error rate: 4.1% (potential scanning/brute force indicator)
- HTTP 5xx error rate: 3.5% (server-side anomalies)
- Response codes over time with annotation markers

![Attack Detection Dashboard](Screenshots/20_dashboard_2_attack_detection.png)

**What this shows:**
- Geographic map of request origins (threat intelligence layer)
- Unique destination heatmap showing traffic patterns by country and hour
- Machine OS distribution for endpoint visibility

---

## Detection Rules

5 custom detection rules were created in Kibana Security — each mapped to a MITRE ATT&CK technique.

**How rules were created:**
- Navigated to Security → Rules → Create New Rule
- Selected Custom Query rule type
- Set index pattern to `kibana_sample_data_logs`
- Wrote KQL detection logic
- Configured severity, risk score, and MITRE tags
- Enabled rule for continuous monitoring

![Detection Rule](Screenshots/09_rule_1_http_anomaly.png)

| Rule | KQL Query | Technique | Severity | Risk Score |
|------|-----------|-----------|----------|------------|
| HTTP 4xx/5xx Anomaly | `http.response.status_code >= 400` | T1190 | Medium | 47 |
| Brute Force Attack | `http.response.status_code: 401` | T1110.001 | High | 73 |
| SQL Injection Detection | `url.original: (*UNION* or *SELECT*)` | T1190 | Critical | 99 |
| Privilege Escalation | `http.response.status_code: 403` | T1548 | High | 73 |
| Data Exfiltration | `bytes > 500000` | T1030 | Critical | 99 |

---

## KQL Threat Hunting Queries

5 KQL queries were built and saved in Kibana Discover for rapid threat investigation. These are ready-to-use queries that an analyst runs when investigating an alert.

**How queries were created:**
- Navigated to Discover → selected `kibana_sample_data_logs` index
- Wrote KQL syntax in the search bar
- Expanded time range to cover all sample data
- Saved each query with a descriptive name for reuse

![KQL Query](Screenshots/14_query_1_failed_auth.png)

| Query | KQL Syntax | Purpose |
|-------|-----------|---------|
| Failed Authentication | `response: "404" or response: "503"` | Identify HTTP error spikes |
| SQL Injection Hunt | `url.original: (*UNION* or *SELECT*)` | Find SQL keywords in URLs |
| Suspicious Transfer | `bytes > 10000` | Large file transfers |
| High Volume IPs | `response: "404"` | IPs generating 404 errors |
| Data Exfiltration | `bytes > 500000` | Extremely large transfers |

---

## Incident Reports

5 complete incident investigation reports were written following professional SOC standards. Each report covers detection, evidence, MITRE mapping, IOCs, root cause, and remediation recommendations.

**How reports were written:**
- Alert fired from detection rule
- KQL queries run to gather evidence
- Attack timeline reconstructed from log data
- MITRE ATT&CK technique identified
- IOCs documented for organization-wide blocking
- Recommendations prioritized by urgency (0-1hr, 1-24hr, 1-7 days)

![Incident Report](Screenshots/22_incident_report_1_brute_force.png)

| # | Incident | Technique | Severity | Status |
|---|----------|-----------|----------|--------|
| 1 | Brute Force Attack | T1110.001 | High | Resolved |
| 2 | SQL Injection Attack | T1190 | Critical | Contained |
| 3 | Privilege Escalation | T1548 | High | Investigating |
| 4 | HTTP Anomaly / Scanning | T1190 | Medium | Contained |
| 5 | Data Exfiltration | T1030 | Critical | Investigating |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Rule | Incident |
|--------|-----------|---------------|---------|
| Initial Access | T1190 — Exploit Public-Facing App | HTTP Anomaly, SQL Injection | #2, #4 |
| Credential Access | T1110.001 — Brute Force | Brute Force Rule | #1 |
| Privilege Escalation | T1548 — Abuse Elevation | Privilege Escalation Rule | #3 |
| Exfiltration | T1030 — Data Transfer Limits | Data Exfiltration Rule | #5 |

---

## Skills Demonstrated

- **Detection Engineering** — Writing KQL-based detection rules for real attack patterns
- **Threat Hunting** — Building saved queries for rapid investigation
- **Log Analysis** — Analyzing web traffic logs to identify anomalies
- **Dashboard Design** — Creating executive-level security visibility
- **Incident Response** — Writing professional investigation reports with IOCs and recommendations
- **MITRE ATT&CK** — Mapping all detections to framework tactics and techniques
- **SIEM Administration** — Configuring and managing Kibana Security module

---

## Repository Structure

Enterprise-ELK-SIEM/

├── README.md

├── INCIDENT-REPORTS/

│   ├── Incident_Report_01_Brute_Force.md

│   ├── Incident_Report_02_SQL_Injection.md

│   ├── Incident_Report_03_Privilege_Escalation.md

│   ├── Incident_Report_04_HTTP_Anomaly.md

│   └── Incident_Report_05_Data_Exfiltration.md

└── Screenshots/

└── (21 screenshots covering all phases)

---

## Author

**Muhammed Anshad V**
Certified SOC Analyst (CSA v2) — EC-Council, 2026
Certified IT Infrastructure and Cyber SOC Analyst (CICSA) — Red Team Hackers Academy, 2026

- Email: mhd.anshad.v@gmail.com
- LinkedIn: https://www.linkedin.com/in/muhemmedanshad
- GitHub: https://github.com/anshadshanu

---
*Last Updated: June 26, 2026*
