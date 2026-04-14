# SOC Investigation Report
## Case: Brute Force Attack — Multiple Failed Logon Attempts
 
---
 
| Field | Detail |
|---|---|
| **Case ID** | INC-2024-0031 |
| **Alert Title** | Brute Force Detection — Multiple Failed Logon Attempts |
| **Severity** | HIGH |
| **Host** | WIN10-SOC-LAB |
| **Account Targeted** | Local user account |
| **Detection Method** | Custom Splunk Alert — "Brute Force Detection - Multiple Failed Logons" |
| **Event ID** | 4625 (An account failed to log on) |
| **Detection Time** | Simulated — multiple 4625 events within a 1-minute window |
| **Analyst** | Eyimofe Samuel Olaiya |
| **Triage Decision** | **ESCALATE — True Positive Confirmed** |
| **Status** | Escalated to Tier 2 / Account lockout review |
 
---
 
## 1. Alert Summary
 
A custom Splunk alert — built and configured by the analyst — triggered after detecting five or more Windows Security Event ID 4625 (Failed Logon) occurrences within a one-minute window on `WIN10-SOC-LAB`. The alert was validated by simulating repeated failed login attempts against the host, which caused the detection rule to fire as expected. All failed logon events originated from the same source, occurred in rapid succession, and resulted in account lockout — a pattern consistent with an automated brute force attack.
 
---
 
## 2. Detection Engineering — Alert Configuration
 
This investigation was initiated by a **custom-built Splunk alert**, not a default rule. The detection logic was authored by the analyst as part of home lab work.
 
**Alert Name:** `Brute Force Detection - Multiple Failed Logons`
 
**SPL Query:**
```spl
index=winsec EventCode=4625
| stats count by Account_Name, src_ip, host
| where count >= 5
```
 
**Alert Conditions:**
- Trigger: 5 or more Event ID 4625 events from the same source within 1 minute
- Schedule: Real-time monitoring
- Severity: High
- Action: Trigger alert and log to notable events
 
**Validation Method:**
The analyst manually simulated brute force activity by entering incorrect credentials repeatedly on `WIN10-SOC-LAB`. The Splunk Universal Forwarder forwarded the generated 4625 events to the Splunk indexer on the Ubuntu VM. The alert fired correctly, confirming the detection rule works as intended.
 
---
 
## 3. Raw Event Log Analysis
 
**Event ID 4625 — Account Logon Failure**
 
Each failed logon attempt generated the following key fields in the Windows Security log:
 
| Field | Value |
|---|---|
| **EventCode** | 4625 |
| **Account_Name** | Target local account |
| **Failure Reason** | Unknown username or bad password |
| **Logon Type** | 3 (Network) / 2 (Interactive) |
| **Source** | WIN10-SOC-LAB |
| **Frequency** | 5+ events within 60 seconds |
| **Final State** | Account lockout triggered |
 
**Why 4625 matters:**
A single 4625 event is not an alert — users mistype passwords. Five or more in rapid succession from the same source, targeting the same account, is the signature of an automated credential attack. The pattern here — consistent timing, same target, no successful logon — removes any plausible legitimate explanation.
 
---
 
## 4. Triage Analysis
 
### Is this behaviour normal?
 
No. Legitimate users do not fail authentication 5+ times within 60 seconds. The velocity and consistency of the failed attempts is characteristic of automated tooling, not human error.
 
### Does this match a known attack technique?
 
Yes — **MITRE ATT&CK T1110.001: Brute Force — Password Guessing.**
 
| Technique | ID | Evidence |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Repeated 4625 events, same account, rapid cadence |
| Account Discovery | T1087 | Attacker enumerating valid accounts via logon failures |
 
### What is the blast radius if untriaged?
 
If this were a production environment and the attack continued:
- Account lockout causes service disruption for the legitimate user
- If the attacker succeeds, they gain initial access to the host
- From there, lateral movement, privilege escalation, and data exfiltration become possible
 
### Can we wait, or is action needed now?
 
Account lockout already occurred, which is a partial natural defence. However escalation is still required to:
1. Confirm whether the attack succeeded before lockout
2. Identify and block the source
3. Review other accounts for similar activity in the same window
 
---
 
## 5. Triage Decision & Reasoning
 
**Decision: ESCALATE — True Positive**
 
The alert fired correctly. The evidence is unambiguous:
 
- Five or more authentication failures in under 60 seconds against a single account
- No corresponding successful logon (Event ID 4624) — attack did not succeed
- Account lockout triggered — confirming attack volume was sufficient to exhaust the threshold
- Pattern matches T1110.001 with no legitimate alternative explanation
 
This is not a false positive. The detection rule performed exactly as designed.
 
### Escalation Note to Tier 2
 
> `WIN10-SOC-LAB` triggered the brute force detection alert after 5+ Event ID 4625 failures within a 1-minute window. Account was locked out — no successful logon (4624) was observed in the same window, indicating the attack did not succeed. Recommend: (1) identify and block the source of the logon attempts, (2) audit all accounts on the host for similar activity in the ±30 minute window, (3) review Event ID 4740 (account lockout) logs to confirm lockout scope, (4) reset affected account credentials as a precaution. No lateral movement indicators found at time of triage.
 
---
 
## 6. Key Indicators of Compromise (IOCs)
 
| Type | Value | Context |
|---|---|---|
| Event ID | 4625 | Failed logon — core detection signal |
| Event ID | 4740 | Account lockout — confirms attack volume |
| Pattern | 5+ failures / 60 seconds | Brute force velocity threshold |
| Logon Type | 2 / 3 | Interactive or network-based attack vector |
 
---
 
## 7. Detection Engineering Notes
 
This case demonstrates the full detection lifecycle:
 
**Build → Test → Validate → Investigate → Document**
 
The SPL query was written to balance sensitivity and specificity — a threshold of 5 events per minute catches real brute force activity while avoiding false positives from occasional mistyped passwords. In a production environment, this threshold would be tuned based on the organisation's baseline failure rate per user.
 
**Potential improvements to the detection rule:**
- Add `src_ip` grouping to catch distributed brute force (low-and-slow attacks across multiple IPs)
- Correlate with Event ID 4740 (lockout) to auto-confirm high-confidence cases
- Add a lookup against known bad IPs to auto-escalate external source attacks
 
---
 
## 8. Lessons Learned
 
**What this case confirms:**
 
Brute force detection is one of the most foundational skills in SOC work — not because the attack is sophisticated, but because **volume and velocity are the signals.** The analyst's job is to recognise that pattern and act before the attacker succeeds.
 
The more important lesson here is the detection engineering side: writing the SPL query, setting the threshold, validating it with simulated data, and confirming the alert fires correctly is exactly what blue team analysts do to harden their environments. Knowing how to *build* detections, not just respond to them, is a differentiator at Tier 1.
 
---
 
*Report filed by: Eyimofe Samuel Olaiya — SOC Analyst (Tier 1)*
*Investigation type: Home lab — detection engineering + alert validation*
*Tools used: Splunk Enterprise 9.1.2, Windows Security Event Logs, Splunk Universal Forwarder*
