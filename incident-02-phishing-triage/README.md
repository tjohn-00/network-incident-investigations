# Incident Report 02: Phishing Email & Dynamic Sandbox Triage

## 1. Executive Summary

A suspicious email sample (`sample-7307.eml`) from `phishing_pot` was flagged for initial SOC triage. Header inspection revealed an RFC 2047 Base64-encoded display name used to evade basic spam filters.

Initial email authentication checks (SPF, DKIM, and DMARC) passed because the message was relayed through legitimate Google Cloud infrastructure (`209[.]85[.]161[.]71`) using an attacker-created Google Firebase container. However, extracted payload links revealed high-risk obfuscation. The primary call-to-action link (`hxxps://is[.]gd/hidateh`) used a public link shortener and triggered 15 behavioral indicators during sandbox detonation. A secondary shortener (`hxxps://is[.]gd/vupivo`) returned a 3/95 malicious verdict on VirusTotal. This campaign abuses trusted cloud hosting and public shorteners to bypass Secure Email Gateways (SEGs).

---

## 2. Environment & Tools 

* **Environment:** Insolated Linux Security VM
* **Raw Sample:** `phishing_pot/email/sample-7307.eml`
* **Parsing & Decoding:** Linux CLI (`grep`, `sed`, `awk`), CyberChef (RFC 2047/ Base64 Header Decoding, URL Defanging) 
* **Dynamic Sandbox:** Hybrid Analysis (CrowdStrike Falcon Sandbox) 
* **Threat Intelligence:** VirusTotal, AbuseIPDB

### Document Callout & Severity Legend

* :red_circle: **Red / Critical:** Confirmed Malicious Indicators (IOCs), high-risk VT scores, or malicious process spawns.
* :orange_circle: **Orange / High:** Suspicious network traffic, redirect chains, or parent execution processes.
* :yellow_circle: **Yellow / Medium:** Obfuscated headers, public link shorteners, or unverified domain redirects.
* :green_circle: **Green / Low:** Verified benign assets, authentic Google cloud infrastructure, and passing security checks (SPF/DKIM/DMARC). 

---

## 3. Header & Authentication Analysis

Routing headers, MIME encoding, and authentication records were checked to verify sender legitimacy and platform authorization. 

| Field | Header / Artifact Value | Triage Finding | Status |
| :--- | :--- | :--- | :--- | 
| **Header Sender (Form)** | `Free Trial Available <noreply@dwcbv-bdb24[.]firebaseapp[.]com>` | RFC 2047 Base64 encoded display name hiding spam lure | :yellow_circle: **ENCODED LURE** | 
| **Return-Path** | `noreply@dwcbv-bdb24[.]firebasesapp[.]com` | Envelope matches From domain; points to free Google Firebase container | :yellow_circle: **SUSPICIOUS (FIREBASE)** |
| **Originating MTA** | `mail-oo1-f71[.]google[.]com` (`209[.]85[.]161[.]71`) | Legitimate Google egress server used to relay message | :green_circle: **LEGIT MTA** |
| **Inbound Gateway** | `*[.]outlook[.]com` (`BL6EF...`, `SJ0PR...`) | Microsoft 365 Exchange Online Protection (EOP) ingestion path | :green_circle: **M365 INGEST** |
| **SPF Record** | `spf=pass` | Originating IP (`209[.]85[.]161[.]71`) authorized for Google Cloud/Firebase | :green_circle: **PASS** | 
| **DKIM Signature** | `v=1; a=rsa-sha256` | Valid cryptographic signature issued by Google Firebase domain | :green_circle: **PASS** | 
| **DMARC Status** | `dmarc=pass` | Domain alignment succeeds (`From` matches `Return-Path` domain) | :green_circle: **PASS (ABUSED INFRA)** | 

### Key Parsed Header Artifact 

```text 
From: =?UTC-8?B?8J+0gUZyZWUgVHJpYWwgQXZhaWxhYmxl?= <noreply@dwcbv-bdb24[.]firebaseapp[.]com>
Return-Path: <noreply@dwcbv-bdb24[.]firebaseapp[.]com>
Received: from mail-oo1-f71[.]google[.]com (209[.]85[.]161[.]71)
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
```

**Analyst Note - Infrastructure Abuse & CyberChef Decoding:**
The `From:` header display name was used RFC 2047 Base64 encoding (`=?UTF-8?B?8J+0gUZyZWUgVHJpYWwgQXZhaWxhYmxl?=`). Running `grep -i "From:" sample-7307.eml` and decoding the payload (`8J+0gUZyZWUgVHJpYWwgQXZhaWxhYmxl`) into CyberChef decoded the lure string to: **`Free Trial Available`**. 

Authentication checks passed because the threat actor created a free Google Firebase app (`dwcbv-bdb24[.]firebasesapp[.]com`) to route mail through Google's trusted infrastructure (`209[.]85[.]161[.]71`), using cloud domain reputation to bypass initial gateway filters.

---

## 4. Extracted URL Assessment & Reputation Lookup

To extract embedded URLs cleanly from the raw sample without corrupting strings, a boundary regex pipeline was used:

```bash
# Extract all HTTP/HTTPS links from the raw email file
grep -a -iEo '(http|https)://[^"<>]+' sample-7307.eml | sed 's^.$//' | sort -u 
```

After defanging the domains, findings were logged into the triage matrix: 

| Extracted URL | Triage Method | VirusTotal / AV Score | Behavioral / Context Findings | Status |
| :--- | :--- | :---| :--- | :--- | 
| **`hxxps://is[.]gd/hidateh`** | Dynamic Sandbox (Hybrid Analysis) | **1/6** (Hybrid Analysis) | 15 Suspicious Indicators; primary call-to-action redirect link | :yellow_circle: **SUSPICIOUS (DETONATED IOC)** |
| **`hxxps://is[.]gd/vupivo`** | Static VT Hash Lookup | :red_circle: **3/95** (VirusTotal) | Secondary shortened URL; flagged across multiple security feeds | :red_circle: **MALICIOUS** |
| **`hxxps://myplatinumtv[.]com/`** | Domain Reputation Lookup | :green_circle: **0/95** (VirusTotal) | Target hosting infrastructure / compromised root domain | :yellow_circle: **SUSPICIOUS** |
| **`hxxps://wa[.]me/18604690175`** | Domain Classification | :yellow_circle: **1/92** (VirusTotal) | Official WhatsApp deep-link; single false-positive engine flag | :green_circle: **BENIGN ASSET** |

**Analyst Note - Multi-Engine Triage & Low-Detection URLs:**
Dynamic detonation of `hxxps://is[.]gd/hidateh` returned a low static AV score (1/6) due to link-shortener abstraction (`is[.]gd`), but triggered **15 dynamic behavioral indicators**. Cross-referencing the secondary link `hxxps://is[.]gd/vupivo` confirmed a multi-stage campaign chaining shorteners to evade SEGs. 

---

## 5. Dynamic Behavioral Analysis (Hybrid Analysis) 

The primary URL (`hxxps://is[.]gd/hidateh`) was denotated in Hybrid Analysis under a controlled Windows 10 64-bit environment.

![Hybrid Analysis Overview](./screenshots/hybrid-overview.png)

*Figure 1: Hybrid Analysis detonation summary.*

**Annotation Legend:**
* :red_circle: **Red Callout Box:** Highlights the threat classification score and dynamic behavioral indicator summary.

---

![Falcon Sandbox Process Tree](./screenshots/process-tree.png)

*Figure 2: Execution graph showing initial process execution.*

**Annotation Legend:**
* :orange_circle: **Orange Callout Box:** Highlights the parent browser process (`chrome.exe`) and initial execution chain during URL navigation. 

---

![Network Connections](./screenshots/network-indicators.png)

*Figure 3: Outbound DNS resolution requests captured during dynamic link detonation.* 

**Annotation Legend**
* :red_circle: **Red Callout Box:** Highlights the outbound DNS query for the `is[.]gd` link shortener domain.
* **Unhighlighted Rows:** Benign background browser telemetry (`mtalk[.]google[.]com`, `ogads-pa[.]clients6[.]google[.]com`).

**Analyst Note - Shared Infrastructure vs. Domain IOCs:**
While the target IP (`104[.]25[.]233[.]53`) belongs to legitimate Cloudflare CDN infrastructure, the dynamic DNS request for `is[.]gd` serves as the actionable host IOC confirming outbound redirection behavior.

---

## 6. MITRE ATT&CK Enterprise Mapping 

| Tactic | Technique ID | Technique Name | Lab Evidence / Observation |
| :--- | :--- | :--- | :--- | 
| **Initial Access** | `T1566.002` | Spearphishing Link | Extracted embedded hyperlinks directing recipient to external infrastructure. | 
| **Resource Development** | `T1583.001` | Domains | Compromised root domain (`myplatinumtv[.]com`) leveraged for hosting assets. | 
| **Defensive Evasion** | `T1027` | Obfuscated Links | Dual link-shorteners URLs (`is[.]gd/hidateh`, `is[.]gd/vupivo`) and Base64 header encoding. | 
| **Defensive Evasion** | `T1497.001` | Sandbox Evasion | Low initial AV detection (1/6) & conditional redirect execution during sandbox analysis. |
| **Defensive Evasion** | `T1656` | Impersonation | Exploitation legitimate cloud service (`firebaseapp[.]com`) reputation to bypass gateway filters. |

---

## 7. Remediation & SOC Recommendations 
 
1. **Secure Email Gateway (SEG) Policy:** Create gateway rules to block or inspect inbound emails containing public link shorteners (`is[.]gd`, `bit[.]ly`, `tinyurl[.]com`).
2. **Cloud Tenant Inspection:** Flag inbound emails from unverified public cloud app subdomains (`firebaseapp[.]com`, `herokuapp[.]com`).
3. **Indicator Blocklist:** Block the identified malicious shortener URLs (`is[.]gd/vupivo`, `is[.]gd/hidateh`) on perimeter firewalls and web proxies.
