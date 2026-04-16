# INC-2024-0048 — Persistence via Registry Run Key Modification

**Analyst:** Eyimofe Samuel Olaiya  
**Date:** 2026-04-16  
**Severity:** High  
**Status:** Resolved (Lab Simulation)  
**MITRE ATT&CK:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder  

---

## Executive Summary

A registry modification event was detected on endpoint WIN-CLIENT-01, targeting the Windows Run key — a common persistence mechanism used by attackers to survive system reboots. The event was captured via Windows Security auditing, forwarded to Splunk via Universal Forwarder, and detected using a custom SPL query. The entry was identified as a simulated malicious payload planted under a deceptive process name designed to blend in with legitimate Windows activity.

---

## Detection Source

| Field | Value |
|---|---|
| SIEM | Splunk 9.1.2 |
| Log Source | Windows Security Event Log |
| Event Code | 4657 — A registry value was modified |
| Index | main |
| Host | WIN-CLIENT-01 |
| Detection Time | 2026-04-16 14:57:44 UTC |

---

## Attack Overview

The Windows Run registry key is a built-in Windows feature that automatically executes any program listed under it every time a user logs in. Attackers abuse this to maintain persistent access — even if the machine is rebooted or the user logs out and back in, the malware continues to execute silently.

This technique requires no special privileges on a standard user account, making it accessible to even unsophisticated attackers. It is one of the oldest and most widely used persistence mechanisms in Windows environments.

**Registry path targeted:**
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

---

## Evidence

### Splunk Detection Query

```spl
index=main source="WinEventLog:Security" EventCode=4657 "CurrentVersion\\Run"
| table _time, ComputerName, Account_Name, Object_Value_Name, New_Value, Process_Name
```

### Event Details

| Field | Value |
|---|---|
| Time | 2026-04-16 14:57:44.653 |
| Computer Name | WIN-CLIENT-01 |
| Account Name | socadmin |
| Object Name | \REGISTRY\USER\...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| Object Value Name | WindowsUpdateHelper |
| New Value | C:\Users\Public\malware.exe |
| Process Name | C:\Windows\regedit.exe |
| Operation Type | Existing registry value modified |
| Keywords | Audit Success |

---

## Analysis

### Indicator 1 — Deceptive Entry Name

The registry entry was named `WindowsUpdateHelper` — a name deliberately chosen to impersonate a legitimate Windows update process. This is a standard attacker technique to avoid raising suspicion during manual log reviews. Legitimate Windows update processes do not register persistence entries in this manner.

### Indicator 2 — Suspicious Payload Path

The value pointed to `C:\Users\Public\malware.exe` — the `Public` folder is a world-writable directory accessible to all users without elevated permissions. Attackers commonly drop payloads here precisely because it does not require administrator access to write to. Legitimate software does not install executables to this location.

### Indicator 3 — Process Context

In this simulation the modification was made via `regedit.exe` — the standard registry editor. In a real attack this field would typically show `powershell.exe`, `cmd.exe`, or a malicious executable — any of which would immediately elevate the severity of this finding. The process name field is one of the most critical fields to examine in any 4657 event.

### Indicator 4 — Multiple Events

Five events were captured across a short timeframe, reflecting the creation, deletion, and recreation of the entry during simulation. In a real incident, multiple modifications to the Run key in rapid succession from the same host would indicate active attacker behaviour rather than accidental or automated changes.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Persistence (TA0003) |
| Technique | Boot or Logon Autostart Execution (T1547) |
| Sub-technique | Registry Run Keys / Startup Folder (T1547.001) |
| Platform | Windows |
| Permissions Required | User |
| Data Source | Windows Registry, Process Monitoring |

---

## Detection Logic

The detection was built around three conditions:

1. **EventCode 4657** — confirms a registry value was written or modified
2. **Path contains CurrentVersion\Run** — scopes the detection specifically to autorun persistence locations
3. **Any single result triggers the alert** — no threshold applied because any modification to this key outside of known software installation activity is inherently suspicious

```spl
index=main source="WinEventLog:Security" EventCode=4657 "CurrentVersion\\Run"
| table _time, ComputerName, Account_Name, Object_Value_Name, New_Value, Process_Name
```

**Alert configuration:**
- Schedule: Every hour
- Trigger: Number of results greater than 0
- Action: Add to Triggered Alerts

---

## Prerequisites for Detection

For this detection to function correctly the following must be configured on the monitored endpoint:

1. **Audit Object Access policy enabled** — via `gpedit.msc → Computer Configuration → Windows Settings → Security Settings → Local Policies → Audit Policy → Audit object access → Success and Failure`

2. **Registry key auditing configured** — the Run key must have auditing enabled for `Everyone` with `Set Value` permission monitored under the Auditing tab in Advanced Security Settings

Without both of these settings active, Windows will not generate 4657 events for registry modifications and the detection will produce no results.

---

## Response Recommendations

In a real incident the following steps would be taken:

1. **Isolate the endpoint** immediately to prevent lateral movement
2. **Identify the payload** at the path specified in `New_Value` — determine if the file exists and submit to VirusTotal or sandbox analysis
3. **Remove the registry entry** to eliminate the persistence mechanism
4. **Review authentication logs** for the affected account — determine if credentials were compromised
5. **Check for additional persistence** — attackers rarely rely on a single mechanism. Review scheduled tasks (Event ID 4698), new user accounts (Event ID 4720), and startup folder contents
6. **Trace the initial access vector** — review proxy and DNS logs around the time of the first registry modification to identify how the attacker gained entry

---

## Lessons Learned

This investigation highlighted an important prerequisite gap in default Windows configurations — registry modification auditing is not enabled out of the box. In enterprise environments this policy must be deployed via Group Policy at scale across all endpoints to ensure visibility. Without it, this class of persistence attack is completely invisible to a SIEM regardless of how well the detection logic is written.

This reinforces a core principle in detection engineering: **a detection is only as good as the logs feeding it.**

---

## References

- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Microsoft Event ID 4657 Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657)
- [Splunk Security Essentials — Registry Monitoring](https://splunkbase.splunk.com/app/3435)

---

*Report generated as part of home SOC lab portfolio. Environment: Splunk 9.1.2 on Ubuntu VM, Windows 10 SOC-LAB VM with Splunk Universal Forwarder, hosted on VMware Workstation 17 Player.*
