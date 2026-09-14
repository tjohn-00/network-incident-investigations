# Incident Report 03: Wazuh SIEM & Host Telemetry Log Hunting

## Project Overview

This project simulates a blue team detection engineering workflow to monitor privilege escalation attempts on Linux endpoints. By deploying custom `auditd` telemetry rules and integrating them with a local Wazuh SIEM instance, this lab establishes real-time visibility into unauthorized or suspicious user-switching activities.

---

## 1. Endpoint Telemetry & Audit Configuration 

To capture execution attempts of the superuser binary (`/usr/bin/su`), a persistent audit rule was configured and loaded into the Linux kernel subsystem.

* **Target Binary:** `/usr/bin/su` (Validated via `which su`) 
* **Audit Rule File:** `/etc/audit/rules.d/user_switch.rules`
* **Rule Syntax:** `-w /usr/bin/su -p x -k user_switch`
* **Verification:** Confirmed rule persistence and kernel state (`enabled=1`) via `auditctl -l`

---

## 2. Wazuh SIEM Detection Engineering 

To parse raw `auditd` logs and elevate them into actionable security telemetry, a custom XML detection rule was authored within Wazuh's flat `local_rules.xml` structure to prevent parser errors (`1220` / `1226`).

```xml
<group name="linux, auditd, privilege_escalation">
  <rule id="100012" level="5">
    <if_matched_sid>80700</if_matched_sid>
    <field name="audit.exe">^/usr/bin/su$</field>
    <description>Linux Endpoint: User switch attempt detected via su execution.</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>
</group>
```
---

## 3. Validation & Testing 

The detection pipeline was validated using Wazuh's local log testing utility (`wazuh-logtest`) to verify that raw `auditd` telemetry maps cleanly to custom Rule `100012`. 

### Logtest Execution Output

```text
Starting wazuh-logtest...
Type: 1
---
phase 1: complete event reading
phase 2: output execution (json)
{
  "timestamp": "2026-09-13T08:00:00.000Z",
  "rule": {
    "level": 5,
    "description": "Linux Endpoint: User switch attempt detected via su execution.",
    "id": "100012",
    "mitre": {
      "id": ["T1078"]
    }
  },
  "decoder": {
    "name": "auditd"
  },
  "data": {
    "audit": {
      "exe": "/usr/bin/su",
      "key": "user_switch"
    }
  }
}
```
---

## 4. SOC Tier 1 Recommendations & Triage Workflow 

When Alert `100012` fires in a production monitoring environment, a Tier 1 analyst should execute the following triage procedure:

1. **Contextualize the Event:** Verify the exact timestamp, hostname, and target account associated with the user-switching attempt.
2. **Examine Parent Process (PPID):** Inspect what application or script spawned the `su` binary. Determine if it was initiated from an interactive terminal session or a background automation script.
3. **Correlate with Authentication Logs:** Cross-reference the alert timestamp with `/var/log/auth.log` to determine whether the authentication attempt succeeded or failed.
4. **Determine True vs. False Positive:** Validate with system administrators or change-management records if the user switch was part of authorized administrative maintenance. Escalate to Tier 2 if unauthorized privilege escalation is suspected.
