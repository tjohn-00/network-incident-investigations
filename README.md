# Security Incident Investigations & Threat Portfolio

Welcome to my security analysis portfolio. This repository contains hands-on incident response investigations, endpoint log analysis, and threat hunting case studies using Wireshark, Wazuh SIEM, ANY.RUN, and Linux CLI tools.   

## Incident Case Studies

| Case Study / Project | Core Triage Vector | Key Tools & Artifacts | Status | 
| :--- | :--- | :--- | :--- |
| **[Incident 01: FormBook Malware C2](./incident-01-formbook-malware)** | Network Forensics | Wireshark, DHCP/Kerberos Attribution, VirusTotal, Defanged IOCs | **Completed** |
| **[Incident 02: Phishing & Sandbox Triage](./incident-02-phishing-triage)** | Email & Malware | ANY.RUN, Header Analysis, CyberChef, Defanged IOCs | **Completed** |
| **[Incident 03: Wazuh SIEM Log Hunting](./incident-03-wazuh-siem)** | Host Telemetry | Wazuh Dashboard, Sysmon, `auditd`, XML Detection Rules | **Completed** | 
| **[Incident 04: SOAR Automation](./incident-04-soar-automation)** | Incident Response Orchestration & Ticketing | Docker, Shuffle, TheHive, Webhooks | **Completed** |
| **[Incident 05: Memory Forensics](./incident-05-memory-forensics)** | RAM Analysis | Volatility 3, public memory dumps, process hooks | **Completed** |
| **[Incident 06: Cloud Security Operations](./incident-06-secops)** | Cloud Identity & Business Email Compromise | AWS CloudTrail / Entra ID JSON logs, `jq`, Python | **Completed** |
| **[Incident 07: Active Directory Attacks](./incident-07-active-directory-attacks)** | AD Enumeration & Lateral Movement | Windows Server Eval, Bloodhound, Event Logs | **Completed** | 
| **[Incident 08: Web Application & API Attack Triage](./incident-08-web-application-api-attack-triage)** | Web Server Log Analysis | Nginx/Apache Access Logs, ModSecurity, `jq`, Python | **Planned** |
| **[Incident 09: Insider Threat & Data Exfiltration](./incident-09-insider-threat-data-exfiltration)** | Behavioral & FIM Triage | Windows Event 4663 (Object Access), Sysmon Event 11, `jq` | **Planned** |
| **[Incident 10: EDR Alert Triage & Tuning](./incident-10-edr-alert-triage-tuning)** | Endpoint & Process Tree Triage | Process Execution Datasets, CyberChef, Wazuh XML Rules | **Planned** | 
