# SOC Investigation Report
## Case: Suspected Lateral Movement via Compromised Service Account

---

| Field | Detail |
|---|---|
| **Case ID** | INC-2024-0047 |
| **Alert Title** | Lateral Movement — Admin Share Access & Credential Tampering |
| **Severity** | HIGH |
| **Host** | WKSTN-031 |
| **Account Involved** | `backup_svc` (service account) |
| **Source IP** | 10.10.50.14 (internal, unassigned asset) |
| **Detection Time** | 23:51:44 |
| **Analyst** | Eyimofe Samuel Olaiya |
| **Triage Decision** | **CONTAIN HOST** |
| **Status** | Escalated to Tier 2 / Incident Response |

---

## 1. Alert Summary

At 23:51:44, the SIEM triggered a HIGH severity alert for suspicious activity on `WKSTN-031`. The `backup_svc` service account logged in over the network from an unrecognised internal IP (`10.10.50.14`), accessed the administrative C$ share, then spawned `cmd.exe` from `services.exe` and executed a command to modify the domain administrator password. This combination of behaviours — off-schedule access, admin share mount, child process from a service, and domain credential modification — was assessed as an active lateral movement incident.

---

## 2. Raw Event Log Timeline

| Time | Event ID | Description | Key Details |
|---|---|---|---|
| 23:51:44 | 4624 | Successful Network Logon | `backup_svc` from `10.10.50.14`, Logon Type 3 |
| 23:51:51 | 5140 | Network Share Accessed | `\\WKSTN-031\C$` — ReadData + WriteData |
| 23:52:01 | 4688 | Process Created | `cmd.exe` spawned by `services.exe` — `cmd /c net user administrator P@ss2024! /domain` |
| 23:52:14 | 4688 | Process Created | `whoami.exe` spawned by `cmd.exe` |

---

## 3. Investigation Steps & Findings

### 3a. Splunk Query — Baseline Behaviour Check

**Query run:** `index=winsec host=WKSTN-031 user=backup_svc | stats count by EventCode, CommandLine | sort -count`

**Findings:**
- `backup_svc` has **no historical record** of network logons to `WKSTN-031`
- The account's normal activity is limited to `FILESVR-01` during the 01:00–03:00 backup window
- No prior instances of `cmd.exe` or `whoami.exe` associated with this account
- **This is anomalous behaviour with no legitimate baseline match**

---

### 3b. Threat Intelligence — Source IP Check

**IP queried:** `10.10.50.14`

**Findings:**
- IP is within the internal `10.10.50.0/24` subnet but is **not assigned to any known asset** in the CMDB
- Not the registered backup server IP
- No prior network activity recorded from this host before 23:51
- Possible indicators: rogue device, pivot machine, or previously compromised internal host
- **Assessment: INTERNAL THREAT — unknown/unauthorised asset acting as the source of this logon**

---

### 3c. User/Account History — Service Account Audit

**Account:** `backup_svc`

**Findings:**
- Scheduled to run only between **01:00 and 03:00** — tonight's activity started at **23:51**, outside its window
- Account permissions are scoped to read access on `FILESVR-01` only — accessing `WKSTN-031\C$` is **outside its authorised scope**
- Account type is a **service account** — it should never interactively spawn `cmd.exe` or run `net user` commands
- Last legitimate recorded activity: 3 nights ago, within the normal backup window
- **Assessment: Account credentials are likely compromised and being abused by a threat actor**

---

### 3d. Network Trace — Lateral Activity Scope

**Findings:**
- `WKSTN-031` made outbound SMB (port 445) connections to:
  - `DC-01` — **Domain Controller**
  - `FILESVR-01` — File server
- Timing: 23:52–23:59 (approximately 7 minutes of active connections post-logon)
- 34 KB outbound to `10.10.50.14` — possible data staging or C2 callback
- **The DC-01 connection is critical — this suggests the attacker attempted to propagate the password change to Active Directory**

---

## 4. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts: Domain Accounts | T1078.002 | `backup_svc` used outside normal context |
| Lateral Tool Transfer / Admin Shares | T1021.002 | `\\WKSTN-031\C$` mounted with write access |
| Windows Command Shell | T1059.003 | `cmd.exe` spawned from `services.exe` |
| Account Manipulation | T1098 | `net user administrator P@ss2024! /domain` |
| System Owner/User Discovery | T1033 | `whoami.exe` executed post-access |
| Remote Services: SMB | T1021.002 | Network logon type 3, SMB to DC and FILESVR |

---

## 5. Triage Decision & Reasoning

**Decision: CONTAIN HOST (WKSTN-031) — Escalate to Tier 2 / Incident Response**

### Why not False Positive?

There is no business justification for `backup_svc` to:
- Log in at 23:51 (outside its scheduled window)
- Access an admin share on a workstation it has no authorised scope over
- Spawn an interactive command shell from a service process
- Attempt to modify the domain administrator password

All four behaviours would need to be explained simultaneously by a legitimate action. No change tickets or maintenance windows were open for this activity.

### Why CONTAIN rather than just ESCALATE?

The command `net user administrator P@ss2024! /domain` represents an **irreversible action** if it successfully replicates to Active Directory. Unlike a brute force attempt (where you can wait for Tier 2 before acting), allowing this host to remain active while the incident is reviewed risks:

1. **Domain administrator credentials being changed** — locking out the security team
2. **The attacker pivoting to DC-01** — network trace confirms that connection was already initiated
3. **Additional hosts being compromised** from `WKSTN-031` as a staging point

The risk of inaction outweighs the disruption of containment. Containment was the correct call.

### Escalation Note to Tier 2

> `WKSTN-031` has been isolated from the network. `backup_svc` credentials should be rotated immediately and audited across all systems. `10.10.50.14` is an unknown internal asset — physical location and owner should be identified. DC-01 event logs should be reviewed for any successful password replication from this incident window (23:51–23:59). Recommend full forensic image of `WKSTN-031` before restoration.

---

## 6. Key Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Internal IP | `10.10.50.14` | Unknown asset, source of suspicious logon |
| Account | `backup_svc` | Compromised service account |
| Process | `cmd.exe` (parent: `services.exe`) | Abnormal parent-child relationship |
| Command | `net user administrator P@ss2024! /domain` | Domain credential tampering |
| Share | `\\WKSTN-031\C$` | Admin share accessed outside authorised scope |

---

## 7. Lessons Learned

**What makes this alert suspicious (and not routine):**

A service account accessing a network share is not inherently suspicious — that is what backup accounts do. What makes this incident stand out is the **combination of anomalies**, not any single one:

- Wrong time + wrong host + wrong process + wrong command = confirmed threat

This is the analyst skill that matters most at Tier 1: recognising that individual events can be explained away, but **correlated anomalies cannot**. The more boxes that don't fit the baseline, the higher your confidence that something is wrong.

**What I would watch for in follow-up:**

- Whether the password change successfully replicated to AD (check DC-01 Event ID 4723/4724)
- Whether any other hosts show logons from `10.10.50.14` in the same window
- Whether `backup_svc` credentials were used elsewhere in the environment

---

*Report filed by: Eyimofe Samuel Olaiya — SOC Analyst (Tier 1)*
*Investigation duration: ~18 minutes*
*Tools used: Splunk SIEM, Internal Threat Intel Feed, Network Flow Logs*
