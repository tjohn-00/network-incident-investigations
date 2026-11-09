# Security Incident Investigations & Threat Portfolio

Welcome to my security analysis portfolio. This repository contains hands-on incident response investigations, endpoint log analysis, and threat hunting case studies using Wireshark, Wazuh SIEM, ANY.RUN, and Linux CLI tools.   

## Incident Case Studies

| Case Study / Project | Core Triage Vector | Key Tools & Artifacts | Status | 
| :--- | :--- | :--- | :--- |
| **[Incident 01: FormBook Malware C2](./incident-01-formbook-malware)** | Network Forensics | Wireshark, DHCP/Kerberos Attribution, VirusTotal, Defanged IOCs | **Completed** |
| **[Incident 02: Phishing & Sandbox Triage](./incident-02-phishing-triage)** | Email & Malware | ANY.RUN, Header Analysis, CyberChef, Defanged IOCs | **Completed** |
| **[Incident 03: Wazuh SIEM Log Hunting](./incident-03-wazuh-siem)** | Host Telemetry | Wazuh Dashboard, Sysmon, `auditd`, XML Detection Rules | **Completed** | 
| **[Incident 04: SOAR Automation](./incident-04-soar-automation)** | Incident Response Orchestration & Ticketing | Docker, Shuffle SOAR, TheHive, Webhooks, Automated API Enrichment (VirusTotal/AbuseIPDB) | **Completed** |
| **[Incident 05: Memory Forensics](./incident-05-memory-forensics)** | RAM Analysis | Volatility 3, Raw Memory Dumps (`.raw`/ `.dmp`), Process Discrepancies (`pslist`/`psscan`), Network Sockets (`netstat`) | **Completed** |
| **[Incident 06: Cloud Security Operations](./incident-06-secops)** | Cloud Identity & Business Email Compromise | AWS CloudTrail, IAM Telemetry, CLI Parsing (`jq`), Sample JSON Datasets | **Completed** |
| **[Incident 07: Active Directory Attacks](./incident-07-active-directory-attacks)** | AD Enumeration & Lateral Movement | Windows Security Event Logs (4624/4672/4768/4104), BloodHound, Local Lab | **Completed** | 
| **[Incident 08: Web Application & API Attack Triage](./incident-08-web-application-api-attack-triage)** | Web Server Log Analysis | NGINX/Apache Access Logs, CLI (`grep`/`awk`), Python-requests Telemetry, Local Linux VM | **Completed** |
| **[Incident 09: Insider Threat & Data Exfiltration](./incident-09-insider-threat-data-exfiltration)** | Behavioral & FIM Triage | Linux `auditd`, File Integrity Monitoring (`audit.log`), CLI (`grep`/`awk`/`uniq`), Local Linux VM | **Completed** |
| **[Incident 10: EDR Alert Triage & Tuning](./incident-10-edr-alert-triage-tuning)** | Endpoint & Process Tree Triage | Local Linux VM, Custom EDR Datasets, CLI (`grep`/`awk`/`cut`), EDR Exclusion Rules | **Completed** | 
