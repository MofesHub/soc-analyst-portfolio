# SOC Investigation Report
## Case: Credential Manager Read — False Positive

---

| Field | Detail |
|---|---|
| **Case ID** | INC-2024-0019 |
| **Alert Title** | Credential Access — Windows Credential Manager Read (Event ID 5379) |
| **Severity** | MEDIUM |
| **Host** | WIN10-SOC-LAB |
| **Account Involved** | Local user account |
| **Detection Method** | Splunk — Windows Security Event ID 5379 |
| **Detection Time** | During home lab monitoring session |
| **Analyst** | Eyimofe Samuel Olaiya |
| **Triage Decision** | **FALSE POSITIVE — Closed** |
| **Status** | Closed — No further action required |

---

## 1. Alert Summary

A medium severity alert fired on `WIN10-SOC-LAB` for Event ID 5379 — a read operation against the Windows Credential Manager. Credential access events are high-signal indicators of attacker activity, particularly credential dumping techniques like LSASS memory access or Credential Manager harvesting (MITRE ATT&CK T1555.004). However, investigation of the reading process, account context, and surrounding activity confirmed this was a legitimate application reading its own stored credentials — a routine operation with no malicious indicators. Alert closed as a false positive.

---

## 2. Raw Event Log Analysis

**Event ID 5379 — Credential Manager Credential Read**

| Field | Value |
|---|---|
| **EventCode** | 5379 |
| **Subject Account** | Local user account |
| **Process** | Legitimate user-facing application |
| **Frequency** | Multiple reads in a short window (application startup) |
| **Timing** | During active user session |
| **Network Activity** | None associated with credential read |

---

## 3. Investigation Steps & Findings

### Step 1 — Process Identification

**Finding:** The credential read was performed by a known, legitimate application installed on the host. The process matched a verified executable with a valid file hash. This is not a tool associated with credential harvesting — it is a standard application that stores and retrieves its own credentials from the Windows Credential Manager at startup.

**Red flag check:** The process reading credentials was NOT one of the commonly abused tools:
- Not `mimikatz.exe`
- Not `procdump.exe`
- Not `lsass.exe` being read externally
- Not `powershell.exe` or `cmd.exe`

### Step 2 — Frequency Analysis

**Finding:** Multiple 5379 events fired in a short window. This is expected — applications often read several stored credentials at startup (saved logins, tokens, cached credentials). A burst of 5379 events from the same process at application launch is a known false positive pattern, not indicative of a credential sweep.

### Step 3 — Network Correlation

**Finding:** Zero outbound network connections from the reading process during or after the credential access. Credential harvesting attacks exfiltrate data — they require network activity. The complete absence of outbound connections removes the exfiltration risk entirely.

### Step 4 — User Context

**Finding:** The credential read occurred during an active, authenticated user session during normal working hours. The account performing the read is the same account that owns the stored credentials — this is self-access, not cross-account credential theft.

---

## 4. Why This Is NOT Malicious

| Indicator | Malicious Pattern | This Case |
|---|---|---|
| Reading Process | `mimikatz`, `procdump`, unknown binary | Known legitimate application |
| File Hash | Unverified or unsigned | Verified — matches known good |
| Network Activity | Outbound to C2 server post-read | None |
| Account Context | Different account reading another's credentials | User reading own stored credentials |
| Timing | Off-hours, no active user session | Active session, business hours |
| Volume | Bulk reads across many accounts | Single application, limited reads |

All indicators point to legitimate application behaviour.

---

## 5. Triage Decision & Reasoning

**Decision: FALSE POSITIVE — Close alert**

Event ID 5379 fired because a legitimate application read its own stored credentials from Windows Credential Manager during an active user session. This is standard application behaviour. No credential harvesting tool, no network exfiltration, no cross-account access. Closing without escalation.

**Closing Note:**
> Event ID 5379 on `WIN10-SOC-LAB` confirmed false positive. Credential read performed by a verified legitimate application during active user session. No outbound network activity. No suspicious process lineage. No cross-account credential access. Recommend tuning alert to exclude known legitimate applications to reduce noise on this event code.

---

## 6. Tuning Recommendation

Event ID 5379 is inherently noisy — nearly every application that stores credentials will generate this event at startup. Effective tuning involves allowlisting known legitimate readers rather than disabling the alert entirely:

```spl
index=winsec EventCode=5379
| where NOT (ProcessName IN ("known_app_1.exe", "known_app_2.exe"))
| stats count by Account_Name, ProcessName, host
| where count > 10
```

This preserves detection for unknown or unexpected processes reading credentials while suppressing routine application noise.

---

## 7. Lessons Learned

**Why credential access alerts are worth investigating even when they resolve as false positives:**

Event ID 5379 is one of the most important event codes to understand because it sits at the intersection of high-value attacker activity and high-volume legitimate behaviour. The analyst cannot afford to dismiss it without investigation — credential theft is a primary objective in most intrusions.

The key distinction is always **who is reading, what they are reading, and where it goes next.** A legitimate application reading its own credentials and doing nothing with them externally is noise. An unknown process reading credentials and immediately initiating an outbound connection is a confirmed threat.

**Building this instinct — distinguishing signal from noise on high-volume event codes — is one of the most valuable skills a T1 analyst can develop.**

---

*Report filed by: Eyimofe Samuel Olaiya — SOC Analyst (Tier 1)*
*Investigation type: Home lab — false positive identification and tuning*
*Tools used: Splunk Enterprise 9.1.2, Windows Security Event Logs*
