# 🔵 SOC Analyst Home Lab — Eyimofe Olaiya

Hands-on SIEM investigations built in a self-configured home lab environment.  
Simulating the alert triage and analysis workflow of a Junior SOC Analyst.

---

## 🛠️ Lab Stack

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation 17 Player |
| SIEM | Splunk Enterprise 9.1.2 (Ubuntu VM) |
| Log Source | Windows 10 VM — Splunk Universal Forwarder (Windows Security logs) |
| Networking | NAT (resolved VMware Player host-only limitation) |

---

## 📁 Investigations

| # | Event ID | Title | Outcome |
|---|---|---|---|
| 1 | 📄 [View Investigation Report — INC-2024-0012](soc-investigations/INC-2024-0012_Scheduled_Task_FP_Report.md) | 4702 | Scheduled Task Modification | False Positive |
| 2 | 📄 [View Investigation Report — INC-2024-0019](soc-investigations/INC-2024-0019_Credential_Manager_FP_Report.md) | 5379 | Credential Manager Read | False Positive |
| 3 | 📄 [View Investigation Report — INC-2024-0031](soc-investigations/INC-2024-0031_Brute_Force_Report.md) | 4625 | Brute Force Attack Detection | True Positive — Alert Fired |
| 4 | 📄 [View Full Investigation Report — INC-2024-0047](soc-investigations/INC-2024-0047_Lateral_Movement_Report.md) | 4624 / 5140 / 4688 | Lateral Movement — Admin Share & Credential Tampering | Escalated + Host Contained |


📄 **[Download Full Portfolio (PDF)](./Eyimofe_Olaiya_SOC_Portfolio.pdf)**

---

## 🧠 Skills Demonstrated

- Splunk SIEM configuration and log ingestion
- Windows Security event log analysis and triage
- SPL (Splunk Processing Language) querying
- Alert investigation: query → pivot → correlate → close
- Brute force detection rule engineering
- False positive identification and documentation

---

## 📬 Contact

**Eyimofe Olaiya** — Toronto, Ontario  
[LinkedIn](https://linkedin.com/in/eyimofeolaiya) | [GitHub](https://github.com/MofesHub)
